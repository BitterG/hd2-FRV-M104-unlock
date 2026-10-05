-- HD2-Addon: mods/dsh/frv_m104
--
-- M-104 INCINERATOR FRV COMPANION STRATAGEM ENGINE (v3.2.0)
-- ==========================================================
-- Binds M-104 Incinerator FRV (StratagemType 135) to M-102 Gunner FRV (StratagemType 105)
-- using the game's native `additional_stratagem` engine field (+200).
--
-- Architecture:
-- 1. Keeps M-102 Gunner FRV 100% stock (Record 0 intact: payload, package, ID).
-- 2. Sets M-102 offset +200 (additional_stratagem) = 135 (M-104 Incinerator FRV).
--    This mirrors the official Eagle Rearm mechanism (where Eagle 500KG has +200 = 49).
-- 3. In M-104 Record 2:
--    - offset +112 = 1 (ShipGeneric origin)
--    - offset +128 = 1 (mission_specific = 1, selectable = 0)
--    - Borrows localized Name & Description pointers from Record 0 so UI displays properly.
-- 4. Result:
--    - Player equips M-102 on ship.
--    - Ship engine automatically loads M-104 as a companion stratagem.
--    - In-mission Ctrl menu shows an independent stratagem option for M-104!
--    - Button code: [4, 3, 2, 4, 3, 1, 1] (Down, Right, Up, Down, Right, Left, Left).
--    - ZERO guest crashes because M-102 is untouched and M-104 uses its native identity.

local M104 = {}
M104.__index = M104

if rawget(_G, 'DshFrvM104') then return rawget(_G, 'DshFrvM104') end
rawset(_G, 'DshFrvM104', M104)

M104.VERSION = 'frv-m104 3.2.0'

-- LDLD signature
M104.STRATAGEM_TYPE = 0x30eb6399

-- Field offsets (stride 400)
M104.OFF_TYPE = 0
M104.OFF_ID = 4
M104.OFF_NAME = 24
M104.OFF_DESC = 32
M104.OFF_PAYLOAD_DESC = 152
M104.OFF_PACKAGE = 168
M104.OFF_ORIGIN = 112
M104.OFF_SELECTABLE = 128
M104.OFF_ADDITIONAL = 200

-- Values
M104.M102_ID = 0xea902c4b
M104.M104_ID = 0xa9a97cd7
M104.M104_TYPE = 135

-- Scheduler constants
M104.START_FRAME = 120
M104.STEP_EVERY = 2
M104.CPU_BUDGET = 0.0015
M104.FIRST_SWEEP_CPU_BUDGET = 0.015
M104.SCAN_CHUNK = 262144
M104.REGION_MIN = 65536
M104.MAX_SWEEPS = 5
M104.FLUSH_EVERY = 300
M104.LOG_LIMIT = 4000

-- ===========================================================================
-- Helpers
-- ===========================================================================
function M104.le_bytes_from_hex(hex)
    return (hex:gsub('%x%x', function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

function M104.u32_to_bytes(val)
    local a = val % 256
    val = math.floor(val / 256)
    local b = val % 256
    val = math.floor(val / 256)
    local c = val % 256
    val = math.floor(val / 256)
    local d = val % 256
    return string.char(a, b, c, d)
end

local function u32(bytes, pos)
    if pos < 1 or pos + 3 > #bytes then return nil end
    local a, b, c, d = string.byte(bytes, pos, pos + 3)
    if not d then return nil end
    return a + b * 256 + c * 65536 + d * 16777216
end

local function u64(bytes, pos)
    local lo = u32(bytes, pos)
    local hi = u32(bytes, pos + 4)
    if not lo or not hi then return nil end
    return lo + hi * 4294967296
end

-- ===========================================================================
-- Windows FFI API
-- ===========================================================================
function M104.resolve_virtual_query(kernel, ffi)
    local ctype = 'size_t (*)(const void *, void *, size_t)'
    local function wrap(symbol)
        if symbol == nil then error('symbol is nil', 0) end
        return function(address, info, size)
            return tonumber(symbol(ffi.cast('const void *', address),
                ffi.cast('void *', info), size))
        end
    end
    local strategies = {
        { name = 'kernel32_cast', run = function() return ffi.cast(ctype, kernel.VirtualQuery) end },
        { name = 'kernel32_direct', run = function() return wrap(kernel.VirtualQuery) end },
    }
    for _, strategy in ipairs(strategies) do
        local ok, result = pcall(strategy.run)
        if ok and result ~= nil then return result, strategy.name end
    end
    return nil, 'resolve_failed'
end

function M104.build_api()
    local ffi = require('ffi')
    assert(ffi.abi('64bit'), 'windows_x64_required')
    ffi.cdef [[
        void *GetCurrentProcess(void);
        int ReadProcessMemory(void *process, const void *address, void *buffer,
                              size_t size, size_t *read);
        int WriteProcessMemory(void *process, void *address, const void *buffer,
                               size_t size, size_t *written);
        uint64_t GetTickCount64(void);
        size_t VirtualQuery(const void *address, void *buffer, size_t length);
        typedef struct {
            void    *BaseAddress;
            void    *AllocationBase;
            uint32_t AllocationProtect;
            uint16_t PartitionId;
            uint16_t Padding;
            size_t   RegionSize;
            uint32_t State;
            uint32_t Protect;
            uint32_t Type;
        } FRVM104_MBI_320;
    ]]
    local kernel = ffi.load('kernel32')
    local virtual_query, via = M104.resolve_virtual_query(kernel, ffi)
    local process = kernel.GetCurrentProcess()
    local mbi = ffi.new('FRVM104_MBI_320[1]')
    local mbi_size = ffi.sizeof(mbi[0])

    local api = { ffi = ffi, kernel = kernel, process = process }

    function api.time()
        return tonumber(kernel.GetTickCount64()) / 1000
    end

    function api.read(address, size)
        if type(address) ~= 'number' or address < 65536 or address + size >= 0x800000000000 or size <= 0 then
            return nil
        end
        local ok, out = pcall(function()
            local buffer = ffi.new('uint8_t[?]', size)
            local read = ffi.new('size_t[1]')
            if kernel.ReadProcessMemory(process, ffi.cast('const void *', address), buffer, size, read) == 0 then
                return nil
            end
            if tonumber(read[0]) ~= size then return nil end
            return ffi.string(buffer, size)
        end)
        if ok and out ~= nil then return out end
        return nil
    end

    function api.write(address, bytes)
        if type(address) ~= 'number' or address < 65536 or address + #bytes >= 0x800000000000 or #bytes <= 0 then
            return false, 'bad_address'
        end
        local ok, result = pcall(function()
            local buffer = ffi.new('uint8_t[?]', #bytes)
            ffi.copy(buffer, bytes, #bytes)
            local written = ffi.new('size_t[1]')
            if kernel.WriteProcessMemory(process, ffi.cast('void *', address), buffer, #bytes, written) == 0 then
                return false
            end
            return tonumber(written[0]) == #bytes
        end)
        return ok and result == true
    end

    function api.regions(min_size)
        local list = {}
        local address = 0x10000
        local guard = 0
        while address < 0x800000000000 and guard < 524288 do
            guard = guard + 1
            local got = tonumber(virtual_query(ffi.cast('const void *', address), ffi.cast('void *', mbi), mbi_size))
            if got ~= mbi_size then break end
            local base = tonumber(ffi.cast('uintptr_t', mbi[0].BaseAddress))
            local size = tonumber(mbi[0].RegionSize)
            if size <= 0 then break end
            local protect = tonumber(mbi[0].Protect)
            local readable = protect == 0x02 or protect == 0x04 or protect == 0x08
                or protect == 0x20 or protect == 0x40 or protect == 0x80
            if tonumber(mbi[0].State) == 0x1000 and readable and size >= (min_size or 0) then
                list[#list + 1] = { base = base, size = size, protect = protect }
            end
            local next_address = base + size
            if next_address <= address then break end
            address = next_address
        end
        table.sort(list, function(a, b)
            if a.size == b.size then return a.base < b.base end
            return a.size < b.size
        end)
        return list
    end

    return api
end

-- ===========================================================================
-- Engine Instance
-- ===========================================================================
function M104.new(opts)
    opts = opts or {}
    local api = opts.api or M104.build_api()

    local appdata = os.getenv and os.getenv('LOCALAPPDATA')
    local dir = appdata and (appdata .. '\\CowboyBingus\\Helldivers2\\Logs') or nil

    local self = setmetatable({
        api = api,
        log_lines = {},
        dir = dir,
        frame = 0,
        phase = 'starting',
        started = false,
        -- Scanning state
        regions = nil,
        region_index = 1,
        region_offset = 0,
        sweeps = 0,
        sweeps_done = 0,
        bytes_scanned = 0,
        census_seen = {},
        strat_instances = {},
        strat_seen = {},
        strat_analyzed_index = 0,
        -- Paired targets
        tables_seen = {},
        bound_targets = {},
        applied_count = 0,
        last_flush_frame = 0,
        restored = false,
    }, M104)

    return self
end

function M104.log(self, msg)
    local line = string.format('[%s f=%d] %s', self.phase, self.frame, msg)
    if #self.log_lines < M104.LOG_LIMIT then
        self.log_lines[#self.log_lines + 1] = line
    end
    if type(print) == 'function' then print('[FRVM104] ' .. line) end
end

function M104.start(self)
    self.started = true
    self:log(string.format('%s | Companion Stratagem Mode Active', M104.VERSION))
    self.phase = 'scanning'
end

-- ===========================================================================
-- Memory Scanner
-- ===========================================================================
function M104.sweep(self, budget)
    if not self.regions then
        local ok, regions = pcall(function() return self.api.regions(M104.REGION_MIN) end)
        if not ok or type(regions) ~= 'table' then return end
        self.regions = regions
        self.region_index = 1
        self.region_offset = 0
        self.sweeps = self.sweeps + 1
        self:log(string.format('sweep_start #%d regions=%d', self.sweeps, #regions))
    end

    local deadline = self.api.time() + budget
    local regions = self.regions

    while self.region_index <= #regions do
        if self.api.time() >= deadline then return end
        local r = regions[self.region_index]
        local chunk = math.min(M104.SCAN_CHUNK, r.size - self.region_offset)
        local cur_addr = r.base + self.region_offset
        local data = self.api.read(cur_addr, chunk)
        if data then
            self.bytes_scanned = self.bytes_scanned + #data
            self:examine_ldld(cur_addr, data)
        end
        self.region_offset = self.region_offset + chunk
        if self.region_offset >= r.size then
            self.region_index = self.region_index + 1
            self.region_offset = 0
        end
    end

    self.regions = nil
    self.sweeps_done = self.sweeps_done + 1
    self:log(string.format('sweep_complete #%d', self.sweeps_done))
end

function M104.examine_ldld(self, base, data)
    local at = 1
    while true do
        at = data:find('LDLD', at, true)
        if not at then break end
        local abs_addr = base + at - 1
        local head = data:sub(at, at + 15)
        at = at + 1
        if not self.census_seen[abs_addr] and #head >= 16 then
            local version = u32(head, 5)
            local type_hash = u32(head, 9)
            local size = u32(head, 13)
            if version == 1 and type_hash == M104.STRATAGEM_TYPE and size and size > 0 then
                self.census_seen[abs_addr] = true
                if not self.strat_seen[abs_addr] then
                    self.strat_seen[abs_addr] = true
                    self.strat_instances[#self.strat_instances + 1] = { address = abs_addr, size = size }
                    self:log(string.format('StratagemSettings table at 0x%X size=%d', abs_addr, size))
                end
            end
        end
    end
end

-- ===========================================================================
-- Table Analyzer: Pair M-102 (Host) & M-104 (Companion)
-- ===========================================================================
function M104.analyze_table(self, instance)
    if self.tables_seen[instance.address] then return end
    local desc = self.api.read(instance.address + 24, 16)
    if not desc then return end
    local records_start = u64(desc, 1)
    local count = u64(desc, 9)
    if not records_start or not count or count <= 0 or count > 128 then return end

    local stride = 400
    local block = self.api.read(records_start, count * stride)
    if not block then return end

    local rec102 = nil
    local rec104 = nil

    for index = 0, count - 1 do
        local rec_base = records_start + index * stride
        local sid = u32(block, index * stride + M104.OFF_ID + 1)
        if sid == M104.M102_ID then
            rec102 = rec_base
        elseif sid == M104.M104_ID then
            rec104 = rec_base
        end
    end

    if rec102 and rec104 then
        self.tables_seen[instance.address] = true
        self.bound_targets[#self.bound_targets + 1] = {
            instance = instance.address,
            rec102 = rec102,
            rec104 = rec104,
            state = 'candidate',
        }
        self:log(string.format('FOUND FRV PAIR in table 0x%X: M-102 at 0x%X, M-104 at 0x%X',
            instance.address, rec102, rec104))
    end
end

-- ===========================================================================
-- Companion Hook Application
-- ===========================================================================
function M104.apply_companion(self)
    local b_one = string.char(1)
    local b_add = M104.u32_to_bytes(M104.M104_TYPE) -- 135

    for _, pair in ipairs(self.bound_targets) do
        if pair.state == 'candidate' then
            -- 1. Read donor localized text pointers from M-102 (Record 0)
            local donor_name = self.api.read(pair.rec102 + M104.OFF_NAME, 8)
            local donor_desc = self.api.read(pair.rec102 + M104.OFF_DESC, 8)

            -- 2. Configure M-104 (Record 2) as an independent companion stratagem
            local ok_n = donor_name and self.api.write(pair.rec104 + M104.OFF_NAME, donor_name)
            local ok_d = donor_desc and self.api.write(pair.rec104 + M104.OFF_DESC, donor_desc)
            local ok_o = self.api.write(pair.rec104 + M104.OFF_ORIGIN, b_one) -- ShipGeneric
            local ok_s = self.api.write(pair.rec104 + M104.OFF_SELECTABLE, b_one) -- Companion available

            -- 3. Set M-102 (Record 0) additional_stratagem (+200) = 135 (M-104)
            local ok_add = self.api.write(pair.rec102 + M104.OFF_ADDITIONAL, b_add)

            -- Verification
            local ver_o = ok_o and self.api.read(pair.rec104 + M104.OFF_ORIGIN, 1) == b_one
            local ver_s = ok_s and self.api.read(pair.rec104 + M104.OFF_SELECTABLE, 1) == b_one
            local ver_add = ok_add and self.api.read(pair.rec102 + M104.OFF_ADDITIONAL, 4) == b_add

            if ver_o and ver_s and ver_add then
                pair.state = 'applied'
                self.applied_count = self.applied_count + 1
                self.phase = 'active'
                self:log(string.format('COMPANION BOUND: M-102 at 0x%X -> additional_stratagem=135 (M-104 at 0x%X)',
                    pair.rec102, pair.rec104))
            else
                pair.state = 'failed'
                self:log(string.format('ERROR: Failed companion binding in table 0x%X', pair.instance))
            end
        end
    end
end

function M104.restore_all(self)
    if self.restored then return 0 end
    self.restored = true
    local b_zero4 = string.rep('\0', 4)
    local b_zero1 = '\0'
    local b_three = string.char(3)

    for _, pair in ipairs(self.bound_targets) do
        if pair.state == 'applied' then
            self.api.write(pair.rec102 + M104.OFF_ADDITIONAL, b_zero4)
            self.api.write(pair.rec104 + M104.OFF_ORIGIN, b_zero1)
            self.api.write(pair.rec104 + M104.OFF_SELECTABLE, b_three)
        end
    end
    self:flush()
end

-- ===========================================================================
-- Lifecycle Step & Attach
-- ===========================================================================
function M104.step(self)
    if self.phase == 'failed' then return end
    if not self.started then self:start(); return end
    if self.frame < M104.START_FRAME then return end

    -- Continuously analyze any discovered tables
    while self.strat_analyzed_index < #self.strat_instances do
        local inst = self.strat_instances[self.strat_analyzed_index + 1]
        self.strat_analyzed_index = self.strat_analyzed_index + 1
        pcall(function() self:analyze_table(inst) end)
    end

    -- Apply companion bindings to newly found pairs
    self:apply_companion()

    -- Run memory sweeps
    if self.sweeps < M104.MAX_SWEEPS then
        local budget = (self.sweeps == 0 and M104.FIRST_SWEEP_CPU_BUDGET) or M104.CPU_BUDGET
        self:sweep(budget)
    end
end

function M104.status_text(self)
    local verdict
    if self.applied_count > 0 then
        verdict = string.format('OK - M-104 Companion Stratagem ACTIVE (%d table(s) bound)', self.applied_count)
    else
        verdict = string.format('WORKING - %s (sweeps %d/%d, %.0f MB scanned)',
            self.phase, math.min(self.sweeps + 1, M104.MAX_SWEEPS),
            M104.MAX_SWEEPS, self.bytes_scanned / 1048576)
    end
    return table.concat({
        verdict,
        'addon=' .. M104.VERSION,
        'bound_tables=' .. tostring(self.applied_count),
    }, '\n')
end

function M104.flush(self)
    if not self.dir then return end
    pcall(function()
        local h1 = io.open(self.dir .. '\\FRVM104_STATUS.txt', 'w')
        if h1 then h1:write(self:status_text() .. '\n'); h1:close() end
        local h2 = io.open(self.dir .. '\\FRVM104.log', 'w')
        if h2 then h2:write(table.concat(self.log_lines, '\n') .. '\n'); h2:close() end
    end)
    self.last_flush_frame = self.frame
end

function M104.attach(self)
    local previous = update
    if type(previous) ~= 'function' then return false end
    local unpack_results = table.unpack or unpack
    local function pack_results(...) return { n = select('#', ...), ... } end
    local mine
    mine = function(...)
        local results = pack_results(previous(...))
        if not self.retired then
            self.frame = self.frame + 1
            if self.frame % M104.STEP_EVERY == 0 then
                pcall(function() self:step() end)
            end
            if self.frame - self.last_flush_frame >= M104.FLUSH_EVERY then
                pcall(function() self:flush() end)
            end
        end
        return unpack_results(results, 1, results.n)
    end
    update = mine
    self.retire_hook = function()
        self.retired = true
        pcall(function() self:restore_all() end)
        if update == mine then update = previous end
    end
    rawset(_G, 'DshFrvM104Retire', self.retire_hook)
    return true
end

if not rawget(_G, 'DshFrvM104Test') then
    local ok, instance = pcall(function() return M104.new({}) end)
    if ok and instance then
        instance:attach()
        pcall(function() instance:start() end)
    end
end

return M104
