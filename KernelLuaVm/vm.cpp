#include "vm.hpp"
#include "lua/state.hpp"
#include "lua/api.hpp"
#include "lua/callback.hpp"

#include <intrin.h>
#pragma intrinsic(_enable)

// - Instance pool -
//
// Fixed pool of up to MAX_INSTANCES independent Lua VMs. Instance 0 is the
// legacy "global" VM (NTLUA_RUN / NTLUA_RESET target it); its log session is
// the pool-backed `logger::global` session. Instances 1..N-1 get their own
// pool-allocated sessions and are managed via NTLUA_INSTANCE_*.
//
namespace vm
{
    vm_instance instances[ MAX_INSTANCES ] = {};
    static KSPIN_LOCK pool_lock;

    static void init_registry( vm_instance* inst )
    {
        for ( int i = 0; i < vm_instance::MAX_TEARDOWN_CALLBACKS; i++ )
            inst->teardown_refs[ i ] = LUA_NOREF;
        for ( int i = 0; i < vm_instance::MAX_TRACKED_PATCHES; i++ )
            inst->patches[ i ] = {};
        inst->patch_conflicts = 0;
    }

    logger::session* create_session()
    {
        logger::session* session = ( logger::session* ) ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof( logger::session ), 'NtLs' );
        if ( session )
            RtlZeroMemory( session, sizeof( *session ) );
        return session;
    }

    void destroy_session( logger::session* session )
    {
        if ( session && session != logger::global )
            ExFreePool( session );
    }

    vm_instance* alloc()
    {
        KIRQL irql;
        KeAcquireSpinLock( &pool_lock, &irql );

        vm_instance* result = nullptr;
        for ( int i = 0; i < MAX_INSTANCES; i++ )
        {
            vm_instance* inst = &instances[ i ];
            if ( !inst->active )
            {
                inst->active = true;
                inst->id = ( uint32_t ) i;
                inst->worker_running = false;
                inst->worker_active  = false;
                inst->worker_thread_handle = nullptr;
                init_registry( inst );
                result = inst;
                break;
            }
        }

        KeReleaseSpinLock( &pool_lock, irql );
        return result;
    }

    void free( vm_instance* inst )
    {
        if ( !inst )
            return;
        stop_worker( inst );
        KIRQL irql;
        KeAcquireSpinLock( &pool_lock, &irql );
        if ( ( size_t ) inst->id < MAX_INSTANCES && &instances[ inst->id ] == inst )
            inst->active = false;
        KeReleaseSpinLock( &pool_lock, irql );
    }

    // - Per-instance execution context -
    // begin_ctx/end_ctx bracket one chunk of Lua execution under the
    // instance's lock. They attach the instance's process if one is selected,
    // and restore CR8/interrupts on exit. detach/attach_* are the Lua-facing
    // process-attach helpers; each resolves the owning instance from the
    // caller's lua_State.
    //
    void begin_ctx( vm_instance* inst )
    {
        inst->context_owner = ( void* ) KeGetCurrentThread();
        inst->context_active = true;
        if ( inst->attached_process )
        {
            if ( PsGetProcessExitStatus( inst->attached_process ) != STATUS_PENDING )
            {
                ObDereferenceObject( inst->attached_process );
                inst->attached_process = nullptr;
            }
            else
            {
                KeStackAttachProcess( inst->attached_process, &inst->apc_state );
                inst->process_attached = true;
            }
        }
    }
    void end_ctx( vm_instance* inst )
    {
        __writecr8( 0 );
        _enable();
        if ( inst->process_attached )
        {
            KeUnstackDetachProcess( &inst->apc_state );
            inst->process_attached = false;
        }
        inst->context_active = false;
        inst->context_owner = nullptr;
    }

    bool detach( vm_instance* inst )
    {
        if ( !inst->context_active || inst->context_owner != ( void* ) KeGetCurrentThread() )
            return false;
        if ( inst->process_attached )
        {
            KeUnstackDetachProcess( &inst->apc_state );
            inst->process_attached = false;
        }
        ObDereferenceObject( inst->attached_process );
        inst->attached_process = nullptr;
        return true;
    }
    bool attach_process( vm_instance* inst, PEPROCESS process )
    {
        if ( !inst->context_active || inst->context_owner != ( void* ) KeGetCurrentThread() )
            return false;
        if ( !ObReferenceObjectSafe( process ) )
            return false;

        if ( inst->process_attached )
            KeUnstackDetachProcess( &inst->apc_state );
        inst->process_attached = false;
        if ( inst->attached_process )
            ObDereferenceObject( inst->attached_process );
        inst->attached_process = process;
        KeStackAttachProcess( process, &inst->apc_state );
        inst->process_attached = true;
        return true;
    }
    bool attach_pid( vm_instance* inst, uint64_t pid )
    {
        if ( !inst->context_active || inst->context_owner != ( void* ) KeGetCurrentThread() )
            return false;

        PEPROCESS process = nullptr;
        PsLookupProcessByProcessId( ( HANDLE ) pid, &process );
        if ( !process )
            return false;

        return attach_process( inst, process );
    }

    vm_instance* lua_owner( lua_State* L )
    {
        return ( vm_instance* ) lua::get_context( L )->vm_owner;
    }

    vm_instance* by_id( uint32_t id )
    {
        if ( id >= MAX_INSTANCES )
            return nullptr;
        vm_instance* inst = &instances[ id ];
        return inst->active ? inst : nullptr;
    }

    // - Per-instance worker thread -
    //
    // Polls `worker()` on a fixed cadence (100ms if the last poll succeeded,
    // 5000ms if it errored or the global was missing). Runs at PASSIVE_LEVEL;
    // takes the instance lock for the duration of one chunk, mirroring the
    // legacy user-mode poll. Stops cleanly when worker_stop_event is
    // signalled (during INSTANCE_DESTROY or driver unload).
    //
    static VOID NTAPI worker_thread_proc( PVOID start_context )
    {
        vm_instance* inst = ( vm_instance* ) start_context;
        bool prev_success = false;

        while ( 1 )
        {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000 * ( prev_success ? 100 : 5000 );
            NTSTATUS wait_status = KeWaitForSingleObject(
                &inst->worker_stop_event, Executive, KernelMode, FALSE, &timeout );
            if ( wait_status == STATUS_SUCCESS )
                break;  // stop_event signalled - exit

            // User toggled the worker off - sleep and re-check. We avoid a
            // tight loop by waiting again on the same event with the long
            // timeout, but only if the toggle just flipped; the next poll
            // will pick up the new state.
            //
            if ( !inst->worker_running )
            {
                prev_success = false;
                continue;
            }

            // Skip if the instance has no Lua state (mid-reset, mid-create).
            //
            if ( !inst->L )
            {
                prev_success = false;
                continue;
            }

            // Try to acquire the instance lock. Skip this tick if the
            // callback bridge is mid-dispatch - the callback path owns the
            // lock and we don't want to queue behind a real handler.
            //
            unique_lock try_g{ inst->lock, false };
            if ( !try_g.acquired )
            {
                prev_success = false;
                continue;
            }

            // Re-check L under the lock: shutdown may have destroyed it
            // while we were sleeping.
            //
            if ( !inst->L )
            {
                prev_success = false;
                continue;
            }

            // Bracket like execute: attach the instance's selected process so
            // worker() can detach/attach like any other script.
            //
            logger::route_begin( inst->log_session );
            begin_ctx( inst );
            prev_success = lua::poll_worker( inst->L );
            end_ctx( inst );
            logger::route_end();

            // try_g releases on scope exit. prev_success is captured before.
        }

        PsTerminateSystemThread( STATUS_SUCCESS );
    }

    void start_worker( vm_instance* inst )
    {
        if ( !inst || inst->worker_active )
            return;

        KeInitializeEvent( &inst->worker_stop_event, NotificationEvent, FALSE );
        inst->worker_running = true;
        inst->worker_active  = true;

        NTSTATUS status = PsCreateSystemThread(
            &inst->worker_thread_handle, 0, nullptr, nullptr, nullptr,
            &worker_thread_proc, inst );

        if ( !NT_SUCCESS( status ) )
        {
            inst->worker_active = false;
            inst->worker_thread_handle = nullptr;
        }
        // On success inst->worker_thread_handle is RETAINED so stop_worker can
        // join the thread. It is closed after the join (or never leaked: the
        // handle dies with the driver process, and the thread is always joined
        // before unload returns).
    }

    // Signals the worker to stop and waits for it to exit (bounded). On
    // return the worker thread has fully terminated, so the slot may be
    // deactivated / reused and the driver unloaded without racing - or
    // executing code from - a live worker.
    //
    void stop_worker( vm_instance* inst )
    {
        if ( !inst || !inst->worker_active )
            return;

        KeSetEvent( &inst->worker_stop_event, IO_NO_INCREMENT, FALSE );
        inst->worker_active = false;

        // The worker may be sleeping up to 5s (idle timeout). The join
        // bounded at 10s folds that in and gives a wedged worker (script that
        // blocks the instruction-budget hook can only delay, not deadlock)
        // room to unwind before we give up.
        //
        if ( inst->worker_thread_handle )
        {
            PETHREAD thread = nullptr;
            if ( NT_SUCCESS( ObReferenceObjectByHandle(
                     inst->worker_thread_handle, THREAD_ALL_ACCESS,
                     *PsThreadType, KernelMode, ( PVOID* ) &thread, nullptr ) ) )
            {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -10000i64 * 10000;  // 10s
                KeWaitForSingleObject( thread, Executive, KernelMode, FALSE, &timeout );
                ObDereferenceObject( thread );
            }
            ZwClose( inst->worker_thread_handle );
            inst->worker_thread_handle = nullptr;
        }
    }

    // Instance 0 is created at DriverEntry (after logger::init and
    // callback::init). It carries the legacy global session.
    //
    void init()
    {
        KeInitializeSpinLock( &pool_lock );
        for ( int i = 0; i < MAX_INSTANCES; i++ )
            instances[ i ].lock.init();

        vm_instance* inst = alloc();
        if ( !inst )
            return;

        inst->log_session = logger::global;
        inst->L = lua::init();
        if ( !inst->L )
            return;

        lua::expose_api( inst->L );
        lua::set_context_owner( inst->L, inst );
        callback::expose_api( inst->L );
        start_worker( inst );
    }

    void shutdown()
    {
        for ( int i = 0; i < MAX_INSTANCES; i++ )
        {
            vm_instance* inst = &instances[ i ];
            if ( !inst->active || !inst->L )
                continue;

            stop_worker( inst );

            unique_lock _g{ inst->lock };
            callback::run_teardown( inst );
            callback::destroy( inst );
            lua::destroy( inst->L );
            inst->L = nullptr;
            destroy_session( inst->log_session );
            inst->log_session = nullptr;
            inst->active = false;
        }
    }
};