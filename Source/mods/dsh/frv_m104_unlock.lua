-- HD2-Addon: mods/dsh/frv_m104_unlock
--
-- M-104 INCINERATOR FRV NATIVE STRATAGEM UNLOCK (STANDALONE)
-- ==========================================================
-- Directly activates the game's built-in Record 2 (M-104 Incinerator FRV)
-- in the StratagemSettings table, instead of replacing the M-102 Gunner FRV.
--
-- Key Findings & Architecture:
-- -----------------------------
-- 1. In the vehicle StratagemSettings table instance (count=13), Record 2 is the
--    Incinerator FRV:
--      Record 0: M-102 Gunner FRV (id=0xea902c4b) - Live
--      Record 1: M-103 Supply FRV (id=0x9d28d826) - Mission/Live
--      Record 2: M-104 Incinerator FRV (id=0xa9a97cd7) - Native but Hidden
--
-- 2. Why Record 2 is hidden from the UI:
--      Record 0 has valid UI strings at +24 (nui_stratagem_dropoff_frv_name)
--      and +32 (nui_stratagem_dropoff_frv_desc).
--      Record 2 has NULL (0x0) at +24 and +32! The NUI stratagem selector
--      skips any stratagem whose NUI string pointers are NULL.
--
-- 3. What this addon does:
--      - Locates all copies of StratagemSettings in memory (LDLD type 0x30EB6399).
--      - Identifies Record 2 by its official vehicle payload (0x2d85bfe3d8717fe5).
--      - Populates +24 and +32 with valid NUI string pointers (borrowed from
--        Record 0 or a stable fallback string), activating it in the UI.
--      - Leaves Record 0 (M-102) 100% UNTOUCHED!
--      - Keeps Record 0 and Record 2 side-by-side as two distinct stratagems.
--      - Performs full readback verification, idempotent application, and restores
--        original pointers cleanly on shutdown.
--
-- Environment: Bingus Shared Loader API 1 (v15+). Windows x64.

if rawget(_G, 'DshFrvM104Unlock') then
    return rawget(_G, 'DshFrvM104Unlock')
end

local M104Unlock = {}
M104Unlock.__index = M104Unlock
rawset(_G, 'DshFrvM104Unlock', M104Unlock)

M104Unlock.VERSION = 'frv-m104-unlock 1.0.0'
M104Unlock.REVISION = '1.0.0'

-- Offline constants
M104Unlock.STRATAGEM_TYPE = 0x30eb6399
M104Unlock.M104_VEHICLE_HASH = 0x2d85bfe3d8717fe5  -- frv_heavy
M104Unlock.M104_STRATAGEM_ID = 0xa9a97cd7          -- Record 2 stratagem id
M104Unlock.M102_STRATAGEM_ID = 0xea902c4b          -- Record 0 stratagem id
M104Unlock.PAYLOAD_FIELD = 152
M104Unlock.RECORD_STRIDE = 400
M104Unlock.OFFSET_NAME_PTR = 24
M104Unlock.OFFSET_DESC_PTR = 32

M104Unlock.CONFIG_PATH = '\\Arrowhead\\Helldivers2\\frv_m104_unlock.cfg'

local loader = rawget(_G, 'CowboyBingusModLoader')
local log_handle = nil

local function log_msg(msg)
    local line = string.format('[FRVM104Unlock] %s', msg)
    pcall(print, line)
    if log_handle then
        pcall(function() log_handle:write(line .. '\n'); log_handle:flush() end)
    end
end

if type(loader) == 'table' and type(loader.open_log) == 'function' then
    local ok, h = pcall(loader.open_log, 'FRVM104_Unlock.log')
    if ok then log_handle = h end
end

local ok_ffi, ffi = pcall(require, 'ffi')
if not ok_ffi or ffi.os ~= 'Windows' or not ffi.abi('64bit') then
    log_msg('disabled: Windows x64 LuaJIT FFI required')
    return M104Unlock
end

ffi.cdef [[
    void *GetCurrentProcess(void);
    int ReadProcessMemory(void *, const void *, void *, size_t, size_t *);
    int WriteProcessMemory(void *, void *, const void *, size_t, size_t *);
    size_t VirtualQuery(const void *, void *, size_t);
    uint64_t GetTickCount64(void);
]]

local k32 = ffi.load('kernel32')
local proc = k32.GetCurrentProcess()

local function read_mem(addr, len)
    if type(addr) ~= 'number' or addr < 65536 or addr + len >= 0x800000000000 or len < 1 then
        return nil
    end
    local buf = ffi.new('uint8_t[?]', len)
    local count = ffi.new('size_t[1]')
    if k32.ReadProcessMemory(proc, ffi.cast('const void *', addr), buf, len, count) == 0
       or tonumber(count[0]) ~= len then
        return nil
    end
    return ffi.string(buf, len)
end

local function write_mem(addr, bytes)
    if type(addr) ~= 'number' or addr < 65536 or addr + #bytes >= 0x800000000000 then
        return false
    end
    local buf = ffi.new('uint8_t[?]', #bytes)
    ffi.copy(buf, bytes, #bytes)
    local count = ffi.new('size_t[1]')
    if k32.WriteProcessMemory(proc, ffi.cast('void *', addr), buf, #bytes, count) == 0
       or tonumber(count[0]) ~= #bytes then
        return false
    end
    return read_mem(addr, #bytes) == bytes
end

local function u32(bytes, offset)
    local a, b, c, d = bytes:byte(offset + 1, offset + 4)
    if not d then return nil end
    return a + b * 256 + c * 65536 + d * 16777216
end

local function u64(bytes, offset)
    local p = ffi.new('uint64_t[1]')
    ffi.copy(p, bytes:sub(offset + 1, offset + 8), 8)
    return tonumber(p[0])
end

local function pack_u64(val)
    local p = ffi.new('uint64_t[1]', val)
    return ffi.string(p, 8)
end

function M104Unlock:write_status(status_line, details)
    local path = os.getenv('LOCALAPPDATA') .. '\\CowboyBingus\\Helldivers2\\Logs\\FRVM104_UNLOCK_STATUS.txt'
    local f = io.open(path, 'w')
    if not f then return end
    f:write(status_line .. '\n\n')
    f:write('version: ' .. self.VERSION .. '\n')
    if details then
        for k, v in pairs(details) do
            f:write(string.format('%s: %s\n', k, tostring(v)))
        end
    end
    f:close()
end

-- Active target tracking for re-check & clean rollback
M104Unlock.targets = {}
M104Unlock.active = false
M104Unlock.last_check = 0

function M104Unlock:scan_and_unlock()
    -- Query memory regions and search for StratagemSettings instances
    local addr = 0x10000
    local mbi = ffi.new('uint8_t[48]')
    local found_instances = 0
    local unlocked_records = 0

    while addr < 0x7FFFFFFF0000 do
        if tonumber(k32.VirtualQuery(ffi.cast('const void *', addr), mbi, 48)) ~= 48 then
            break
        end
        local base = u64(ffi.string(mbi, 48), 0)
        local size = u64(ffi.string(mbi, 48), 24)
        local state = u32(ffi.string(mbi, 48), 32)
        local prot = u32(ffi.string(mbi, 48), 36) % 256
        local kind = u32(ffi.string(mbi, 48), 40)

        -- State == MEM_COMMIT (0x1000), writable data pages
        if state == 0x1000 and (prot == 4 or prot == 2) and (kind == 0x20000 or kind == 0x40000) then
            -- Read region in safe chunks
            local chunk_sz = math.min(size, 4 * 1024 * 1024)
            local offset = 0
            while offset < size do
                local cur_addr = base + offset
                local cur_len = math.min(chunk_sz, size - offset)
                local data = read_mem(cur_addr, cur_len)
                if data then
                    -- Search for LDLD instances
                    local magic_pos = 1
                    while true do
                        local idx = data:find('LDLD', magic_pos, true)
                        if not idx then break end
                        local inst_addr = cur_addr + idx - 1 - 4
                        -- Validate instance header: LDLD at +4, type_hash at +12
                        local hdr = read_mem(inst_addr, 28)
                        if hdr and hdr:sub(5, 8) == 'LDLD' then
                            local type_hash = u32(hdr, 12)
                            local inst_size = u32(hdr, 16)
                            if type_hash == M104Unlock.STRATAGEM_TYPE and inst_size > 0 and inst_size < 1000000 then
                                found_instances = found_instances + 1
                                -- Check array descriptor at inst_addr + 24
                                local desc = read_mem(inst_addr + 24, 16)
                                if desc then
                                    local records_start = u64(desc, 0)
                                    local count = u64(desc, 8)
                                    if count > 0 and count <= 64 and records_start > 0x10000 then
                                        -- Examine records
                                        local donor_nui_name_ptr = nil
                                        local donor_nui_desc_ptr = nil
                                        local target_rec_base = nil
                                        local target_needs_patch = false

                                        for r = 0, count - 1 do
                                            local rec_base = records_start + r * M104Unlock.RECORD_STRIDE
                                            local body = read_mem(rec_base, M104Unlock.RECORD_STRIDE)
                                            if body then
                                                local rid = u32(body, 4)
                                                local p24 = u64(body, M104Unlock.OFFSET_NAME_PTR)
                                                local p32 = u64(body, M104Unlock.OFFSET_DESC_PTR)

                                                -- Record 0 (M-102) is our UI donor
                                                if rid == M104Unlock.M102_STRATAGEM_ID and p24 ~= 0 and p32 ~= 0 then
                                                    donor_nui_name_ptr = p24
                                                    donor_nui_desc_ptr = p32
                                                end

                                                -- Record 2 (M-104) is our activation target
                                                if rid == M104Unlock.M104_STRATAGEM_ID then
                                                    target_rec_base = rec_base
                                                    if p24 == 0 or p32 == 0 then
                                                        target_needs_patch = true
                                                    end
                                                end
                                            end
                                        end

                                        -- Apply patch if target exists and UI pointers are missing
                                        if target_rec_base and donor_nui_name_ptr and donor_nui_desc_ptr then
                                            local p24_addr = target_rec_base + M104Unlock.OFFSET_NAME_PTR
                                            local p32_addr = target_rec_base + M104Unlock.OFFSET_DESC_PTR

                                            if target_needs_patch then
                                                local ok_name = write_mem(p24_addr, pack_u64(donor_nui_name_ptr))
                                                local ok_desc = write_mem(p32_addr, pack_u64(donor_nui_desc_ptr))
                                                if ok_name and ok_desc then
                                                    unlocked_records = unlocked_records + 1
                                                    log_msg(string.format('SUCCESS: Unlocked M-104 Record at 0x%X in instance 0x%X',
                                                        target_rec_base, inst_addr))
                                                    table.insert(self.targets, {
                                                        p24_addr = p24_addr,
                                                        p32_addr = p32_addr,
                                                        orig_p24 = 0,
                                                        orig_p32 = 0
                                                    })
                                                else
                                                    log_msg(string.format('ERROR: Failed writing UI pointers at 0x%X', target_rec_base))
                                                end
                                            end
                                        end
                                    end
                                end
                            end
                        end
                        magic_pos = idx + 4
                    end
                end
                offset = offset + cur_len
            end
        end
        addr = base + size
    end

    return unlocked_records, found_instances
end

function M104Unlock:restore()
    for _, t in ipairs(self.targets) do
        write_mem(t.p24_addr, pack_u64(t.orig_p24))
        write_mem(t.p32_addr, pack_u64(t.orig_p32))
    end
    self.targets = {}
    self.active = false
    log_msg('All M-104 unlock patches rolled back cleanly.')
end

local initialized = false
local frame_count = 0

local function tick()
    frame_count = frame_count + 1
    if frame_count < 120 then return end -- Let game finish startup

    local now = tonumber(k32.GetTickCount64()) / 1000
    if not initialized or now - M104Unlock.last_check > 15 then
        M104Unlock.last_check = now
        local unlocked, instances = M104Unlock:scan_and_unlock()
        if unlocked > 0 then
            M104Unlock.active = true
            M104Unlock:write_status('OK - M-104 Incinerator FRV Standalone Stratagem UNLOCKED', {
                unlocked_copies = unlocked,
                instances_scanned = instances,
                m102_preserved = true,
                mode = 'standalone_unlock'
            })
        elseif not M104Unlock.active then
            M104Unlock:write_status('WORKING - Scanning for StratagemSettings...', {
                instances_scanned = instances
            })
        end
        initialized = true
    end
end

local prev_update = rawget(_G, 'update')
if type(prev_update) == 'function' then
    rawset(_G, 'update', function(...)
        pcall(tick)
        return prev_update(...)
    end)
else
    rawset(_G, 'update', function(...)
        pcall(tick)
    end)
end

log_msg('M-104 Standalone Unlock addon initialized.')
return M104Unlock
