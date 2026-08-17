R"(
    -- Named, offset-based field access over the read/write primitives.
    -- Field specs:  Name = offset                 (defaults to 8 bytes)
    --               Name = { offset, size }       (1/2/4/8 or >8 = raw bytes)
    --               Name = { offset, size, type=T } (nested struct at offset)
    --               Name = { offset, size, ptr=T }  (read8 then deref, nil if 0)

    struct = {}

    function struct.read_bytes(addr, n)
        local bytes = {}
        for i = 0, n - 1 do
            bytes[#bytes + 1] = string.char(read1(addr + i))
        end
        return table.concat(bytes)
    end

    function struct.write_bytes(addr, s)
        for i = 1, #s do
            write1(addr + i - 1, string.byte(s, i))
        end
    end

    local methods = {
        address = function(t) return t._addr end,
        -- Write the (possibly modified) snapshot buffer back to the process
        -- and address it was read from. Field writes mutate the snapshot in
        -- place, so this pushes the whole working copy back.
        write = function(t)
            if not t._target_addr or not t._keep then
                return nil
            end
            return write_process_memory(t._pid, t._target_addr, t._keep)
        end,
    }

    local function normalize(spec)
        if type(spec) == "number" then
            return { offset = spec, size = 8 }
        end
        if spec.offset then
            return { offset = spec.offset, size = spec.size or 8,
                     type = spec.type, ptr = spec.ptr }
        end
        return { offset = spec[1], size = spec[2] or 8,
                 type = spec.type, ptr = spec.ptr }
    end

    local function read_field(f, base)
        local addr = base + f.offset
        if f.type then
            return f.type(addr)
        elseif f.ptr then
            local p = read8(addr)
            if p == 0 then return nil end
            return f.ptr(p)
        elseif f.size == 1 then
            return read1(addr)
        elseif f.size == 2 then
            return read2(addr)
        elseif f.size == 4 then
            return read4(addr)
        elseif f.size == 8 then
            return read8(addr)
        else
            return struct.read_bytes(addr, f.size)
        end
    end

    local function write_field(f, base, value)
        local addr = base + f.offset
        if f.type or f.ptr then
            error("cannot write to a struct/ptr field")
        elseif f.size == 1 then
            write1(addr, value)
        elseif f.size == 2 then
            write2(addr, value)
        elseif f.size == 4 then
            write4(addr, value)
        elseif f.size == 8 then
            write8(addr, value)
        else
            struct.write_bytes(addr, value)
        end
    end

    function struct.define(fields)
        local normalized = {}
        for name, spec in pairs(fields) do
            normalized[name] = normalize(spec)
        end

        local mt = {}
        mt.__index = function(t, key)
            local f = normalized[key]
            if f then return read_field(f, t._addr) end
            return methods[key]
        end
        mt.__newindex = function(t, key, value)
            local f = normalized[key]
            if f then
                write_field(f, t._addr, value)
            else
                rawset(t, key, value)
            end
        end
        mt.__tostring = function(t)
            return string.format("struct @ 0x%016X", t._addr & 0xFFFFFFFFFFFFFFFF)
        end

        local function bind(addr)
            return setmetatable({ _addr = addr }, mt)
        end

        -- A struct type is a callable table: TYPE(addr) binds, and TYPE.read
        -- snapshots process memory into a buffer. (A bare function can't hold
        -- extra fields in Lua, hence the table + __call.)
        local T = setmetatable({}, {
            __call = function(_, addr) return bind(addr) end,
        })

        function T.read(pid, addr, size)
            local bytes = read_process_memory(pid, addr, size)
            if not bytes then return nil end
            local inst = bind(addressof(bytes))
            rawset(inst, "_keep", bytes)
            rawset(inst, "_pid", pid)
            rawset(inst, "_target_addr", addr)
            return inst
        end

        return T
    end
)"
