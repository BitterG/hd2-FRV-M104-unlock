-- HD2-Addon: mods/dsh/frv_m104_recon
--
-- M-104 INCINERATOR FRV - PHASE 1: READ-ONLY RECONNAISSANCE
-- ---------------------------------------------------------------------------
-- Goal: make the M-102 Gunner FRV stratagem deliver the M-104 Incinerator FRV
-- instead of the standard FRV.
--
-- What is already established offline (M104-FRV-Replacer/tools/):
--
--   * All three FRV variants are *separate unit resources* in the entity blob:
--         content/fac_helldivers/vehicles/frv/frv                  0xcc21c7ffd3ebefb9  M-102
--         content/fac_helldivers/vehicles/frv_supply/frv_supply    0x9b2140378640432e  M-103
--         content/fac_helldivers/vehicles/frv_heavy/frv_flamer     0x2d85bfe3d8717fe5  M-104
--     `frv_heavy/frv_flamer` is the Incinerator: the wiki describes the M-104 as
--     "heavier armour, a spiked ramming grille and a roof-mounted heavy
--     flamethrower at the expense of seating", and that unit's component set is
--     exactly what those differences are made of.
--   * `generated_stratagem_settings.dl_bin` is the one table the offline mirror
--     does not cover (FileDiver does not parse it) and the community JSON for it
--     stopped at 2024-10-29 - more than a year before the FRV existed.  So the
--     M-102 record can only be read from the running game.
--   * The payload convention was verified against the only vehicle stratagems we
--     *can* read offline: the two Exosuit records carry
--         payload = [ <unit resource>, 0x75be82ed8592a6b3 ]
--     and every one of those values is a unit that really exists in the entity
--     blob's component index tables.  So `payload[0]` is "the unit to spawn".
--
-- Therefore phase 2 is expected to be: find the StratagemSettings record whose
-- payload holds 0xcc21c7ffd3ebefb9 and overwrite that u64 with 0x2d85bfe3d8717fe5.
-- This addon exists to prove that and to hand back the exact record layout, so
-- phase 2 does not have to guess an offset.
--
-- What this addon does - and deliberately does NOT do:
--
--   * It NEVER writes to game memory: there is no WriteProcessMemory and no
--     VirtualProtect anywhere in this file.  It never patches code: GameGuard
--     shuts the game down for that.
--   * It sweeps committed memory in <=1.5 ms CPU slices, 256 KB at a time, and
--     writes everything it finds to
--     %LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs\ :
--       - a census of every resident LDLD data table (address, type hash, size),
--       - every occurrence of the four FRV-related 64-bit ids and of the entity
--         blob's 20-byte header signature, each with a hex dump around it and a
--         classification (inside a StratagemSettings table / inside the entity
--         blob / somewhere else),
--       - for every resident StratagemSettings table: the array descriptor
--         decoded both ways (memory pointer and file-relative offset), which
--         record stride follows from the header size and the record count, which
--         record and which field offset holds each FRV id, and a full hex dump
--         of the table so the layout can be fixed offline if the guesses are wrong.
--
-- How to run it: start the game once and leave it on the ship for about a minute,
-- then start a mission and leave that for another minute, then quit.  Send back
-- FRVM104Recon_STATUS.txt plus every frv_m104_*.txt in the same folder.
--
-- Environment: Bingus Shared Loader API 1 (v15+).  Windows x64.

if rawget(_G, 'DshFrvM104Recon') then
    return rawget(_G, 'DshFrvM104Recon')
end

local Recon = {}
Recon.__index = Recon
rawset(_G, 'DshFrvM104Recon', Recon)

Recon.VERSION = 'frv-m104-recon 1.0.0'
Recon.REVISION = 'recon-1.0.0'

-- ===========================================================================
-- 1. Offline-derived constants (M104-FRV-Replacer/tools/verify_identity.py)
-- ===========================================================================
-- GENERATED-BEGIN (plain marker: this file must stay free of Lua-5.3 operators)
-- generated from the plaintext datalibrary mirror; do not edit by hand

-- the entity blob's first 20 bytes; this string occurs exactly once in the blob,
-- so it anchors the in-memory image the way the M-103 mod anchors its record
Recon.BLOB_SIGNATURE = '70cac1804c444c440100000070cac1809ecd0200'

-- 64-bit resource ids, little-endian on the wire
Recon.IDS = {
    { label = 'frv_base',   hex = 'b9efebd3ffc721cc', value = 0xcc21c7ffd3ebefb9 },
    { label = 'frv_supply', hex = '2e4340863740219b', value = 0x9b2140378640432e },
    { label = 'frv_heavy',  hex = 'e57f71d8e3bf852d', value = 0x2d85bfe3d8717fe5 },
    { label = 'delivery',   hex = 'b3a69285ed82be75', value = 0x75be82ed8592a6b3 },
}

-- djb2 of 'StratagemSettings' - the LDLD type tag of generated_stratagem_settings
Recon.STRATAGEM_TYPE = 0x30eb6399

-- LDLD type tags the census knows by name (everything else prints as a hash)
Recon.TYPES = {
    { hash = 0x30eb6399, name = 'StratagemSettings' },
    { hash = 0x7bd60854, name = 'StratagemInfo' },
    { hash = 0xbd4042c2, name = 'ProjectileSettings' },
    { hash = 0xe0a72cf0, name = 'DamageSettings' },
}

-- ===========================================================================
-- 2. Policy
-- ===========================================================================
Recon.START_FRAME = 120          -- 6.5: let the game finish loading first
Recon.STEP_EVERY = 2             -- drive one slice every two frames
Recon.CPU_BUDGET = 0.0015        -- 6.42: hard per-slice CPU budget
Recon.SCAN_CHUNK = 262144        -- 6.14: small enough for the deadline to bite
Recon.OVERLAP = 64               -- keep patterns that straddle a chunk boundary
Recon.REGION_MIN = 65536
Recon.READ_LIMIT = 1048576            -- 1 MiB
Recon.MAX_SWEEPS = 5
Recon.SWEEP_BACKOFF = { 5, 20, 45, 90, 150 }
Recon.RELOAD_GROWTH = 1.2        -- 6.8: a mission load grows the address space
Recon.FLUSH_EVERY = 300          -- frames between periodic dumps
Recon.LOG_LIMIT = 4000
Recon.HIT_DETAIL_LIMIT = 1024
Recon.CENSUS_LIMIT = 4000
Recon.DUMP_BEFORE = 256
Recon.DUMP_AFTER = 768
Recon.DUMP_LIMIT = 32            -- per pattern
Recon.DUMP_BYTES_LIMIT = 1024
Recon.HIT_DUMP_TOTAL = 3145728        -- 3 MiB
Recon.STRAT_DUMP_LIMIT = 16      -- copies of the stratagem table to dump in full
Recon.STRAT_DUMP_BYTES = 262144  -- per copy
Recon.REGION_REPORT = 400
Recon.RECORD_HIT_LIMIT = 64

-- the header of one LDLD instance is 28 bytes:
--   +0 u32 type_hash | +4 char magic[4] | +8 u32 version | +12 u32 type
--   +16 u32 size     | +20 u8 is64      | +21 u8 pad[7]
Recon.INSTANCE_HEADER = 28
Recon.PAYLOAD_OFFSET = 24        -- from the magic position, i.e. header - 4

-- ===========================================================================
-- 3. Small helpers (pure Lua; LuaJIT is 5.1: no bit ops, no 5.3 syntax)
-- ===========================================================================

local HEX = {}
for i = 0, 255 do HEX[i] = string.format('%02x', i) end

function Recon.hex(bytes, limit)
    local out = {}
    local count = #bytes
    if limit and count > limit then count = limit end
    for i = 1, count do
        out[i] = HEX[string.byte(bytes, i)]
    end
    return table.concat(out)
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

Recon.u32, Recon.u64 = u32, u64

function Recon.le_bytes_from_hex(hex)
    -- 6.1: build the byte string from hex pairs, never through a Lua number
    return (hex:gsub('%x%x', function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

-- ===========================================================================
-- 4. Windows API
-- ===========================================================================

function Recon.build_api()
    local ffi = require('ffi')
    assert(ffi.abi('64bit'), 'windows_x64_required')
    ffi.cdef [[
        void *GetCurrentProcess(void);
        void *GetModuleHandleA(const char *module_name);
        int ReadProcessMemory(void *process, const void *address, void *buffer,
                              size_t size, size_t *read);
        uint64_t GetTickCount64(void);
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
        } FRVM104_MBI_9c41;
    ]]
    -- 6.52: never declare VirtualQuery against a generic anonymous struct name -
    -- ffi.cdef accumulates across mods and the prototype binds to whichever
    -- struct was declared first.  The name above is private to this addon.
    assert(ffi.sizeof('FRVM104_MBI_9c41') == 48, 'unsupported_mbi_layout')

    local kernel = ffi.load('kernel32')
    local process = kernel.GetCurrentProcess()
    local mbi = ffi.new('FRVM104_MBI_9c41[1]')
    local mbi_size = ffi.sizeof(mbi[0])
    local ok, virtual_query = pcall(function()
        return ffi.cast('size_t (*)(const void *, void *, size_t)',
            kernel.VirtualQuery)
    end)
    if not ok or virtual_query == nil then
        virtual_query = ffi.cast('size_t (*)(const void *, void *, size_t)',
            ffi.C.VirtualQuery)
    end

    local api = { ffi = ffi, name = 'windows' }

    function api.time()
        return tonumber(kernel.GetTickCount64()) / 1000
    end

    function api.read(address, size)
        if type(address) ~= 'number' or address < 65536
            or address + size >= 0x800000000000
            or size <= 0 or size > Recon.READ_LIMIT then
            return nil
        end
        -- 6.4: the address has to be a real pointer; only true FFI catches a
        -- bare Lua number here, which is why the test stub is type-strict.
        local ok_read, out = pcall(function()
            local buffer = ffi.new('uint8_t[?]', size)
            local count = ffi.new('size_t[1]')
            if kernel.ReadProcessMemory(process, ffi.cast('const void *', address),
                    buffer, size, count) == 0 then
                return nil
            end
            if tonumber(count[0]) ~= size then return nil end
            return ffi.string(buffer, size)
        end)
        if not ok_read then return nil end
        return out
    end

    function api.regions(min_size)
        local list = {}
        local address = 0x10000
        local guard = 0
        while address < 0x800000000000 and guard < 524288 do
            guard = guard + 1
            local got = tonumber(virtual_query(ffi.cast('const void *', address),
                ffi.cast('void *', mbi), mbi_size))
            if got ~= 48 then break end
            local base = tonumber(ffi.cast('uintptr_t', mbi[0].BaseAddress))
            local size = tonumber(mbi[0].RegionSize)
            if size <= 0 then break end
            local protect = tonumber(mbi[0].Protect)
            local readable = protect == 0x02 or protect == 0x04 or protect == 0x08
                or protect == 0x20 or protect == 0x40 or protect == 0x80
            if tonumber(mbi[0].State) == 0x1000 and readable
                and size >= (min_size or 0) then
                list[#list + 1] = { base = base, size = size, protect = protect }
            end
            local next_address = base + size
            if next_address <= address then break end
            address = next_address
        end
        table.sort(list, function(a, b)
            if a.size == b.size then return a.base < b.base end
            return a.size > b.size
        end)
        return list
    end

    function api.string_address(text)
        local got, value = pcall(function()
            return tonumber(ffi.cast('uintptr_t',
                ffi.cast('const char *', text)))
        end)
        if got then return value end
        return nil
    end

    function api.module(name)
        local handle = kernel.GetModuleHandleA(name)
        if handle == nil then return nil end
        local value = tonumber(ffi.cast('uintptr_t', handle))
        if value == 0 then return nil end
        return value
    end

    return api
end

-- ===========================================================================
-- 5. Construction
-- ===========================================================================

function Recon.safe_now()
    if type(os) == 'table' and type(os.date) == 'function' then
        return os.date('!%Y-%m-%dT%H:%M:%SZ')
    end
    return 'unknown'
end

function Recon.default_dir()
    local appdata = os.getenv and os.getenv('LOCALAPPDATA')
    if not appdata or appdata == '' then return nil end
    return appdata .. '\\CowboyBingus\\Helldivers2\\Logs'
end

function Recon.new(opts)
    opts = opts or {}
    local api = opts.api or Recon.build_api()
    -- `dir = false` means "no file output at all" and must NOT fall back to the
    -- player's real %LOCALAPPDATA% log folder - an offline test that writes there
    -- would be writing to the user's machine (the M-103 mod shipped that bug once).
    local dir = opts.dir
    if dir == nil then dir = Recon.default_dir() end
    local self = setmetatable({
        api = api,
        emit = opts.emit or function(line)
            if type(print) == 'function' then
                print('[FRVM104Recon] ' .. line)
            end
        end,
        clock = opts.clock or os.clock,
        dir = dir,
        frame = 0,
        phase = 'starting',
        reason = nil,
        started = false,
        finished = false,
        started_at = Recon.safe_now(),
        -- scanning
        regions = nil,
        region_index = 1,
        region_offset = 0,
        region_count = 0,
        region_total_bytes = 0,
        region_lines_cache = '',
        level_loads = 0,
        sweeps = 0,
        chunks = 0,
        bytes_scanned = 0,
        self_hits = 0,
        next_sweep_at = nil,
        -- findings
        census = {},
        census_lines = {},
        census_seen = {},
        census_count = 0,
        census_dropped = 0,
        hits = {},
        hit_lines = {},
        hit_lines_dropped = 0,
        hit_count = 0,
        dumps = {},
        dump_bytes = 0,
        patterns = {},
        self_patterns = {},
        blob_bases = {},
        strat_instances = {},
        strat_seen = {},
        strat_lines = {},
        strat_dumps = {},
        strat_dump_digests = {},
        strat_analyzed_index = 0,
        strat_analyzed = false,
        record_hits = 0,
        log_lines = {},
        log_dropped = 0,
        files_written = 0,
        last_flush_frame = -1,
    }, Recon)
    return self
end

-- ===========================================================================
-- 6. Patterns and self-detection
-- ===========================================================================

function Recon.init_patterns(self)
    self.patterns = {}
    for _, item in ipairs(Recon.IDS) do
        -- the byte form has to be attached to the IDS entries as well: both the
        -- sweeper and the record scanner search for exactly these bytes, and a
        -- missing field here turns into "string expected, got nil" deep inside a
        -- pcall, where it looks like "no records found" instead of a bug.
        if not item.bytes then
            item.bytes = Recon.le_bytes_from_hex(item.hex)
        end
        self.patterns[#self.patterns + 1] = {
            kind = 'id', label = item.label, value = item.value,
            hex = item.hex, bytes = item.bytes,
            length = 8, hits = 0, dumps = 0, seen = {},
        }
    end
    self.patterns[#self.patterns + 1] = {
        kind = 'blob', label = 'blob_signature', value = nil,
        hex = Recon.BLOB_SIGNATURE,
        bytes = Recon.le_bytes_from_hex(Recon.BLOB_SIGNATURE),
        length = math.floor(#Recon.BLOB_SIGNATURE / 2), hits = 0, dumps = 0, seen = {},
    }
end

function Recon.collect_self_patterns(self)
    self.self_patterns = {}
    local texts = { Recon.BLOB_SIGNATURE }
    for _, item in ipairs(Recon.IDS) do texts[#texts + 1] = item.hex end
    for _, text in ipairs(texts) do
        -- 6.2: our own constants live on the Lua heap, so a whole-address-space
        -- scan WILL find them.  Remember where, and skip those hits later.
        local address = self.api.string_address(text)
        if address and address > 0 then
            self.self_patterns[#self.self_patterns + 1] =
                { address = address, size = #text }
        end
    end
end

function Recon.is_self(self, address)
    for i = 1, #self.self_patterns do
        local pattern = self.self_patterns[i]
        if address >= pattern.address - 8192
            and address <= pattern.address + pattern.size + 8192 then
            return true
        end
    end
    return false
end

function Recon.log(self, line)
    local text = string.format('[%s f=%d] %s', self.phase, self.frame, line)
    if #self.log_lines < Recon.LOG_LIMIT then
        self.log_lines[#self.log_lines + 1] = text
    else
        self.log_dropped = self.log_dropped + 1
    end
    self.emit(line)
end

-- ===========================================================================
-- 7. Sweeping
-- ===========================================================================

function Recon.begin_sweep(self)
    local ok, regions = pcall(function()
        return self.api.regions(Recon.REGION_MIN)
    end)
    if not ok or type(regions) ~= 'table' then
        self.phase = 'failed'
        self.reason = 'region_query_failed'
        self:log('region_query_failed')
        return false
    end
    self.regions = regions
    self.region_index = 1
    self.region_offset = 0
    -- 6.8: not every table is resident from the start - a mission load can be what
    -- brings the stratagem table in.  A big jump in the region count is the cheap
    -- way to notice that, and it refunds one sweep so the budget is not already
    -- spent by the time the table appears.
    local previous = self.region_count
    self.region_count = #regions
    if previous and previous > 0 and #regions > previous * Recon.RELOAD_GROWTH then
        self.level_loads = self.level_loads + 1
        if self.sweeps > 0 then self.sweeps = self.sweeps - 1 end
        self:log(string.format(
            'level_load_detected regions %d -> %d; sweep budget refunded (sweeps=%d)',
            previous, #regions, self.sweeps))
    end
    local total = 0
    for _, region in ipairs(regions) do total = total + region.size end
    self.region_total_bytes = total
    local lines = {
        string.format('# regions >= %d bytes : %d regions, %.0f MB total',
            Recon.REGION_MIN, self.region_count, total / 1048576),
    }
    local limit = math.min(#regions, Recon.REGION_REPORT)
    for i = 1, limit do
        lines[#lines + 1] = string.format('region base=0x%016X size=%d protect=0x%X',
            regions[i].base, regions[i].size, regions[i].protect or 0)
    end
    if #regions > limit then
        lines[#lines + 1] = string.format('... %d more regions', #regions - limit)
    end
    self.region_lines_cache = table.concat(lines, '\n') .. '\n'
    self.phase = 'scanning'
    self:log(string.format('sweep_start #%d regions=%d total_mb=%.0f',
        self.sweeps + 1, self.region_count, total / 1048576))
    return true
end

-- One time-sliced slice of the current sweep.  Returns true when it is complete.
-- 6.42: the CPU deadline is mandatory - without it a multi-MB region is consumed
-- synchronously inside one frame and the game visibly stutters.
function Recon.sweep_slice(self, budget)
    local api = self.api
    if self.regions == nil then
        if not self:begin_sweep() then return true end
    end
    local deadline = self.clock() + (budget or Recon.CPU_BUDGET)
    local regions = self.regions
    local did_one = false
    while true do
        if self.region_index > #regions then
            self.regions = nil
            self.sweeps = self.sweeps + 1
            return true
        end
        if did_one and self.clock() >= deadline then break end
        local region = regions[self.region_index]
        local want = region.size - self.region_offset
        if want <= 0 then
            self.region_index = self.region_index + 1
            self.region_offset = 0
        else
            if want > Recon.SCAN_CHUNK then want = Recon.SCAN_CHUNK end
            local at = region.base + self.region_offset
            local data = api.read(at, want)
            self.chunks = self.chunks + 1
            self.bytes_scanned = self.bytes_scanned + want
            if data then
                pcall(function() self:examine(at, data) end)
            end
            if want >= Recon.OVERLAP * 2 then
                self.region_offset = self.region_offset + want - Recon.OVERLAP
            else
                self.region_offset = self.region_offset + want
            end
            did_one = true
        end
    end
    return false
end

function Recon.examine(self, base, data)
    for _, pattern in ipairs(self.patterns) do
        local at = 1
        local found = 0
        while found < 512 do
            at = data:find(pattern.bytes, at, true)
            if at == nil then break end
            found = found + 1
            pcall(function() self:on_hit(pattern, base + at - 1) end)
            at = at + 1
        end
    end
    pcall(function() self:examine_ldld(base, data) end)
end

function Recon.on_hit(self, pattern, address)
    if self:is_self(address) then
        self.self_hits = self.self_hits + 1
        return
    end
    local key = string.format('%s:%d', pattern.label, address)
    if pattern.seen[key] then return end
    pattern.seen[key] = true
    pattern.hits = pattern.hits + 1
    self.hit_count = self.hit_count + 1

    if pattern.kind == 'blob' then
        self.blob_bases[#self.blob_bases + 1] = address
        if #self.hit_lines < Recon.HIT_DETAIL_LIMIT then
            self.hit_lines[#self.hit_lines + 1] = string.format(
                'hit label=%-18s address=0x%016X kind=entity_blob_base note=blob_image_found',
                pattern.label, address)
        else
            self.hit_lines_dropped = self.hit_lines_dropped + 1
        end
        self:log(string.format('entity blob image at 0x%X', address))
    else
        self.hits[#self.hits + 1] = { label = pattern.label, address = address }
        local where = self:classify(address)
        if #self.hit_lines < Recon.HIT_DETAIL_LIMIT then
            self.hit_lines[#self.hit_lines + 1] = string.format(
                'hit label=%-18s address=0x%016X kind=id where=%s',
                pattern.label, address, where)
        else
            self.hit_lines_dropped = self.hit_lines_dropped + 1
        end
    end
    if pattern.hits <= 32 then
        self:log(string.format('hit %s at=0x%X (n=%d)', pattern.label,
            address, pattern.hits))
    end
    self:dump_around(pattern, address)
end

function Recon.dump_around(self, pattern, address)
    if pattern.dumps >= Recon.DUMP_LIMIT then return end
    if self.dump_bytes >= Recon.HIT_DUMP_TOTAL then return end
    local from = address - Recon.DUMP_BEFORE
    if from < 0x10000 then from = 0x10000 end
    local size = Recon.DUMP_BEFORE + Recon.DUMP_AFTER
    local data = self.api.read(from, size)
    if data == nil then
        self.dumps[#self.dumps + 1] = string.format(
            '# %s address=0x%016X UNREADABLE\n', pattern.label, address)
        pattern.dumps = pattern.dumps + 1
        return
    end
    local lines = {
        string.format('# %s address=0x%016X base=0x%016X bytes=%d frame=%d where=%s',
            pattern.label, address, from, #data, self.frame,
            self:classify(address)),
    }
    local budget = math.min(#data, Recon.DUMP_BYTES_LIMIT)
    for offset = 0, budget - 16, 16 do
        lines[#lines + 1] = string.format('0x%016X  %s', from + offset,
            Recon.hex(data:sub(offset + 1, offset + 16)))
    end
    lines[#lines + 1] = ''
    local text = table.concat(lines, '\n') .. '\n'
    self.dumps[#self.dumps + 1] = text
    self.dump_bytes = self.dump_bytes + #text
    pattern.dumps = pattern.dumps + 1
end

function Recon.classify(self, address)
    for _, instance in ipairs(self.strat_instances) do
        if address >= instance.address - 4
            and address < instance.address + instance.size then
            return string.format('stratagem_table@0x%X+0x%X', instance.address,
                address - instance.address)
        end
    end
    for _, base in ipairs(self.blob_bases) do
        if address >= base and address < base + 67108864 then
            return string.format('entity_blob@0x%X+0x%X', base, address - base)
        end
    end
    return 'unclassified'
end

-- ---------------------------------------------------------------------------
-- LDLD census (6.16 / 6.19: this is what separates "not in memory" from
-- "parsed it wrong")
-- ---------------------------------------------------------------------------
function Recon.examine_ldld(self, base, data)
    local at = 1
    while true do
        at = data:find('LDLD', at, true)
        if at == nil then break end
        local absolute = base + at - 1
        local head = data:sub(at, at + 15)
        at = at + 1
        if not self.census_seen[absolute] and #head >= 16 then
            local version = u32(head, 5)
            local type_hash = u32(head, 9)
            local size = u32(head, 13)
            if version == 1 and type_hash and type_hash ~= 0
                and size and size > 0 and size < 268435456 then
                if self:is_self(absolute) then
                    self.self_hits = self.self_hits + 1
                else
                    self.census_seen[absolute] = true
                    if self.census_count < Recon.CENSUS_LIMIT then
                        self.census_count = self.census_count + 1
                        local name = self:type_name(type_hash)
                        self.census[#self.census + 1] = {
                            address = absolute, type_hash = type_hash,
                            size = size, name = name, frame = self.frame,
                        }
                        self.census_lines[#self.census_lines + 1] = string.format(
                            'ldld address=0x%016X type=0x%08X name=%-24s size=%-9d frame=%d',
                            absolute, type_hash, name, size, self.frame)
                        if type_hash == Recon.STRATAGEM_TYPE then
                            self:register_strat_instance(absolute, size)
                        end
                    else
                        self.census_dropped = self.census_dropped + 1
                    end
                end
            end
        end
    end
end

function Recon.type_name(self, type_hash)
    for _, item in ipairs(Recon.TYPES) do
        if item.hash == type_hash then return item.name end
    end
    return string.format('0x%08X', type_hash)
end

function Recon.register_strat_instance(self, address, size)
    if self.strat_seen[address] then return end
    self.strat_seen[address] = true
    self.strat_instances[#self.strat_instances + 1] = {
        address = address, size = size, frame = self.frame,
    }
    self:log(string.format('StratagemSettings table at 0x%X size=%d',
        address, size))
end

-- ===========================================================================
-- 8. Stratagem table analysis - one table per step, so no frame takes the hit
-- ===========================================================================

-- Returns true when every table seen so far has been analysed.
function Recon.analyze_stratagems(self)
    if self.strat_analyzed_index >= #self.strat_instances then
        self.strat_analyzed = #self.strat_instances > 0
        return true
    end
    local instance = self.strat_instances[self.strat_analyzed_index + 1]
    self.strat_analyzed_index = self.strat_analyzed_index + 1
    pcall(function() self:analyze_one(instance) end)
    if self.strat_analyzed_index >= #self.strat_instances then
        self.strat_analyzed = #self.strat_instances > 0
    end
    return self.strat_analyzed
end

-- 6.19: a failure here must still leave the header and whatever was decoded on
-- disk.  The first version published `lines` only at the very end, so one bad
-- byte anywhere threw the whole analysis away and the log said nothing at all.
function Recon.analyze_one(self, instance)
    local lines = {
        string.format('== StratagemSettings at 0x%016X size=%d first_frame=%d',
            instance.address, instance.size, instance.frame or 0),
    }
    local ok, err = pcall(function() self:analyze_body(instance, lines) end)
    if not ok then
        lines[#lines + 1] = '   ANALYSIS_ERROR: ' .. tostring(err)
    end
    self.strat_lines[#self.strat_lines + 1] = table.concat(lines, '\n')
    pcall(function() self:dump_strat_body(instance, lines) end)
end

function Recon.analyze_body(self, instance, lines)
    local api = self.api
    local address, size = instance.address, instance.size
    local total = math.min(Recon.INSTANCE_HEADER + size, Recon.STRAT_DUMP_BYTES)
    local body = api.read(address - 4, total)
    if body == nil then
        lines[#lines + 1] = '   UNREADABLE'
        return
    end
    lines[#lines + 1] = string.format('   read=%d bytes from 0x%016X',
        #body, address - 4)
    lines[#lines + 1] = string.format('   header=%s', Recon.hex(body:sub(1, 28)))
    lines[#lines + 1] = string.format('   is64=%d', string.byte(body, 21) or -1)

    -- The instance payload begins at magic+24 -> body index 29 (body starts at
    -- magic-4).  Its first 16 bytes are the array descriptor.
    local descriptor = body:sub(29, 44)
    local raw_ptr = u64(descriptor, 1)
    local count = u64(descriptor, 9)
    lines[#lines + 1] = string.format('   descriptor=%s raw_u64_0=%s count=%s',
        Recon.hex(descriptor),
        raw_ptr and string.format('0x%X', raw_ptr) or '?',
        count and tostring(count) or '?')
    instance.raw_ptr, instance.count = raw_ptr, count

    local payload_abs = address + Recon.PAYLOAD_OFFSET
    local stride
    if count and count > 0 and count <= 8192 and size > 16 and (size - 16) % count == 0 then
        stride = (size - 16) / count
    end
    instance.stride = stride
    lines[#lines + 1] = string.format('   derived stride=%s (size-16=%d count=%s)',
        stride and tostring(stride) or 'undecidable', size - 16,
        count and tostring(count) or '?')

    local candidates = {}
    if raw_ptr and count and count > 0 then
        candidates[#candidates + 1] = { how = 'absolute_pointer', at = raw_ptr }
        if raw_ptr < total * 4 then
            candidates[#candidates + 1] = { how = 'relative_offset',
                                            at = payload_abs + raw_ptr }
        end
    end
    -- 6.13: also try "records follow the descriptor", which is the file shape
    candidates[#candidates + 1] = { how = 'inline_after_descriptor',
                                    at = payload_abs + 16 }

    for _, candidate in ipairs(candidates) do
        local probe = api.read(candidate.at, 64)
        lines[#lines + 1] = string.format('   candidate %-24s start=0x%016X first64=%s',
            candidate.how, candidate.at,
            probe and Recon.hex(probe) or 'UNREADABLE')
    end

    -- Scan every candidate that has a usable stride: read the whole record array
    -- in one call and look for our ids.  This is the decisive artefact.
    if stride and stride >= 64 and stride <= 4096 and count and count > 0
        and count <= 8192 then
        local span = count * stride
        if span <= Recon.READ_LIMIT then
            for _, candidate in ipairs(candidates) do
                local array = api.read(candidate.at, span)
                if array == nil then
                    lines[#lines + 1] = string.format(
                        '      array %s UNREADABLE', candidate.how)
                else
                    self:scan_record_array(instance, candidate.how, candidate.at,
                        stride, count, array, lines)
                end
            end
        else
            lines[#lines + 1] = string.format(
                '      array span %d exceeds the read limit; not scanned', span)
        end
    end

end

-- Full hex, de-duplicated: the table has many identical copies in memory and the
-- point of the dump is the layout, not the copy count.
function Recon.dump_strat_body(self, instance, lines)
    local address, size = instance.address, instance.size
    local total = math.min(Recon.INSTANCE_HEADER + size, Recon.STRAT_DUMP_BYTES)
    local body = self.api.read(address - 4, total)
    if body == nil then return end
    local digest = 0
    for i = 1, #body, 97 do
        digest = (digest + string.byte(body, i) * i) % 4294967296
    end
    digest = string.format('%d:%d', #body, digest)
    if self.strat_dump_digests[digest] then
        lines[#lines + 1] = '   (identical to an earlier dump; full hex omitted)'
        return
    end
    if #self.strat_dumps >= Recon.STRAT_DUMP_LIMIT then return end
    self.strat_dump_digests[digest] = true
    local dump = {
        string.format('# full StratagemSettings instance at 0x%016X size=%d '
            .. '(read %d bytes from 0x%016X)',
            address, size, #body, address - 4),
    }
    for offset = 0, #body - 16, 16 do
        dump[#dump + 1] = string.format('0x%016X  %s', address - 4 + offset,
            Recon.hex(body:sub(offset + 1, offset + 16)))
    end
    dump[#dump + 1] = ''
    self.strat_dumps[#self.strat_dumps + 1] = table.concat(dump, '\n') .. '\n'
end

function Recon.scan_record_array(self, instance, how, start, stride, count, array,
                                 lines)
    local hits = 0
    for _, item in ipairs(Recon.IDS) do
        local pos = 1
        while hits < Recon.RECORD_HIT_LIMIT do
            local at = array:find(item.bytes, pos, true)
            if at == nil then break end
            local field = at - 1
            local index = math.floor(field / stride)
            local within = field - index * stride
            if within % 8 == 0 then
                hits = hits + 1
                self.record_hits = self.record_hits + 1
                lines[#lines + 1] = string.format(
                    '      RECORD_HIT where=%-24s %-11s record=%-5d field=+%-5d address=0x%016X',
                    how, item.label, index, within, start + field)
            end
            pos = at + 1
        end
    end
    lines[#lines + 1] = string.format('      array %-24s bytes=%d records=%d hits=%d',
        how, #array, count, hits)
end

-- ===========================================================================
-- 9. Lifecycle
-- ===========================================================================

function Recon.read_module(self)
    local out = { base = nil, image_size = nil, timestamp = nil }
    local api = self.api
    if not api.module then return out end
    local ok, handle = pcall(function() return api.module('game.dll') end)
    if not ok or not handle then return out end
    out.base = handle
    local dos = api.read(handle, 0x1000)
    if dos == nil or dos:sub(1, 2) ~= 'MZ' then return out end
    local pe_offset = u32(dos, 0x3C + 1)
    if pe_offset == nil then return out end
    local pe = api.read(handle + pe_offset, 0x100)
    if pe == nil or pe:sub(1, 4) ~= 'PE\0\0' then return out end
    out.timestamp = u32(pe, 9)
    out.image_size = u32(pe, 24 + 0x38 + 1)
    return out
end

function Recon.check_environment(self)
    local loader = rawget(_G, 'CowboyBingusModLoader')
    local api_level, loader_version = nil, nil
    if type(loader) == 'table' then
        api_level = tonumber(loader.api)
        loader_version = tonumber(loader.version)
    end
    self.loader_api = api_level
    self.loader_version = loader_version
    if api_level ~= nil and api_level < 1 then
        self.phase = 'failed'
        self.reason = string.format(
            'loader_api_too_old (api=%s version=%s); Bingus Shared Loader v15+ required',
            tostring(api_level), tostring(loader_version))
        self:log(self.reason)
        self:flush()
        return false
    end
    self:log(string.format('environment loader_api=%s loader_version=%s',
        tostring(api_level), tostring(loader_version)))
    return true
end

function Recon.start(self)
    if self.started then return end
    self.started = true
    if self.phase == 'failed' then
        self:flush()
        return
    end
    self.phase = 'starting'
    self:init_patterns()
    self:collect_self_patterns()
    self.module = self:read_module()
    self:log(string.format('%s | module_base=%s size_of_image=%s timestamp=%s',
        Recon.VERSION,
        self.module.base and string.format('0x%X', self.module.base) or 'unavailable',
        self.module.image_size and tostring(self.module.image_size) or '?',
        self.module.timestamp and string.format('0x%08X', self.module.timestamp) or '?'))
    if not self:check_environment() then return end
    self.next_sweep_at = self.api.time()
    self:flush()
end

function Recon.step(self)
    if self.finished then return end
    if self.phase == 'failed' then
        self.finished = true
        return
    end
    if not self.started then
        self:start()
        return
    end
    if self.frame < Recon.START_FRAME then return end

    -- one table per step: parsing a copy must never share a frame with a
    -- 256 KB memory sweep
    if self.strat_analyzed_index < #self.strat_instances then
        self:analyze_stratagems()
        return
    end

    local scanning = self.regions ~= nil
        or (self.next_sweep_at ~= nil and self.api.time() >= self.next_sweep_at)
    if scanning then
        self.next_sweep_at = nil
        local done = self:sweep_slice()
        if not done then return end
        if self.phase == 'failed' then
            self.finished = true
            return
        end
        self:log(string.format(
            'sweep_done #%d regions=%d scanned_mb=%.0f hits=%d census=%d strat_tables=%d record_hits=%d',
            self.sweeps, self.region_count, self.bytes_scanned / 1048576,
            self.hit_count, self.census_count, #self.strat_instances,
            self.record_hits))
        self:flush()
    end

    -- The decisive condition: the table is in memory, fully parsed, and one of
    -- its records really holds the M-102 FRV unit id.
    if self.record_hits > 0 and self.strat_analyzed_index >= #self.strat_instances then
        self:finish('done', string.format(
            'stratagem record found: %d record hit(s) across %d table copy/copies',
            self.record_hits, #self.strat_instances))
        return
    end

    if self.sweeps >= Recon.MAX_SWEEPS then
        if #self.strat_instances == 0 then
            self:finish('done', 'no StratagemSettings table found after all sweeps')
        elseif self.record_hits == 0 then
            self:finish('done', 'stratagem table found but no FRV unit id inside it')
        else
            self:finish('done', 'sweeps exhausted')
        end
        return
    end
    if self.next_sweep_at == nil and self.regions == nil then
        local backoff = Recon.SWEEP_BACKOFF[self.sweeps]
            or Recon.SWEEP_BACKOFF[#Recon.SWEEP_BACKOFF]
        self.next_sweep_at = self.api.time() + backoff
        self.phase = 'waiting'
        self:log(string.format('next_sweep_in=%ds', backoff))
    end
end

function Recon.finish(self, phase, reason)
    if self.phase == 'failed' then
        self.finished = true
        self:flush()
        return
    end
    self.phase = phase
    self.reason = reason
    self.finished = true
    self:log(string.format('finished phase=%s reason=%s', phase, tostring(reason)))
    self:flush()
end

-- ===========================================================================
-- 10. Output
-- ===========================================================================

function Recon.write_file(self, name, text)
    if not self.dir then return false end
    if type(io) ~= 'table' or type(io.open) ~= 'function' then return false end
    local path = self.dir .. '\\' .. name
    local ok = pcall(function()
        local handle = io.open(path, 'w')
        if not handle then return end
        handle:write(text)
        handle:flush()
        handle:close()
    end)
    if ok then
        self.files_written = self.files_written + 1
        return true
    end
    return false
end

function Recon.census_lines_all(self)
    local lines = {
        string.format('# LDLD census: %d blocks (dropped=%d) sweeps=%d scan_mb=%.0f self_hits=%d',
            self.census_count, self.census_dropped, self.sweeps,
            self.bytes_scanned / 1048576, self.self_hits),
    }
    for _, line in ipairs(self.census_lines) do lines[#lines + 1] = line end
    return lines
end

function Recon.status_text(self)
    local verdict
    if self.phase == 'failed' then
        verdict = 'FAILED - ' .. tostring(self.reason)
    elseif self.finished then
        verdict = string.format(
            'OK - recon complete: %d LDLD blocks, %d stratagem table copy/copies, '
            .. '%d FRV record hit(s)',
            self.census_count, #self.strat_instances, self.record_hits)
    else
        verdict = string.format('WORKING - %s (sweeps %d/%d, %.0f MB scanned)',
            self.phase, math.min(self.sweeps + 1, Recon.MAX_SWEEPS),
            Recon.MAX_SWEEPS, self.bytes_scanned / 1048576)
    end
    local counts = {}
    for _, pattern in ipairs(self.patterns) do
        counts[#counts + 1] = string.format('%s=%d', pattern.label, pattern.hits)
    end
    local lines = {
        verdict,
        'addon=' .. Recon.VERSION,
        'purpose=read-only recon: make the M-102 Gunner FRV stratagem spawn the M-104 Incinerator FRV',
        'phase=' .. self.phase,
        'reason=' .. tostring(self.reason),
        'frames=' .. tostring(self.frame),
        'loader_api=' .. tostring(self.loader_api),
        'loader_version=' .. tostring(self.loader_version),
        'game_dll_base=' .. ((self.module and self.module.base)
            and string.format('0x%X', self.module.base) or 'unavailable'),
        'game_dll_size_of_image=' .. tostring(self.module and self.module.image_size),
        'game_dll_pe_timestamp=' .. ((self.module and self.module.timestamp)
            and string.format('0x%08X', self.module.timestamp) or 'unavailable'),
        'sweeps=' .. tostring(self.sweeps) .. '/' .. tostring(Recon.MAX_SWEEPS),
        'regions=' .. tostring(self.region_count),
        'region_mb=' .. string.format('%.0f', self.region_total_bytes / 1048576),
        'scanned_mb=' .. string.format('%.0f', self.bytes_scanned / 1048576),
        'hits=' .. tostring(self.hit_count) .. ' ' .. table.concat(counts, ' '),
        'ldld_blocks=' .. tostring(self.census_count),
        'ldld_dropped=' .. tostring(self.census_dropped),
        'level_loads=' .. tostring(self.level_loads),
        'stratagem_tables=' .. tostring(#self.strat_instances),
        'stratagem_tables_analysed=' .. tostring(self.strat_analyzed_index),
        'stratagem_record_hits=' .. tostring(self.record_hits),
        'entity_blob_bases=' .. tostring(#self.blob_bases),
        'self_hits_skipped=' .. tostring(self.self_hits),
        'dumped_bytes=' .. tostring(self.dump_bytes),
        'started_at=' .. self.started_at,
        'files=frv_m104_census.txt frv_m104_hits.txt frv_m104_stratagem.txt '
            .. 'frv_m104_stratagem_dump.txt frv_m104_dump.txt '
            .. 'frv_m104_regions.txt FRVM104Recon.log',
        '',
        'SEND BACK: this file plus every frv_m104_*.txt in this folder.',
    }
    return table.concat(lines, '\n') .. '\n'
end

function Recon.flush(self)
    self:write_file('FRVM104Recon_STATUS.txt', self:status_text())
    self:write_file('FRVM104Recon.log', table.concat(self.log_lines, '\n') .. '\n')
    self:write_file('frv_m104_census.txt',
        table.concat(self:census_lines_all(), '\n') .. '\n')
    self:write_file('frv_m104_hits.txt', table.concat(self.hit_lines, '\n') .. '\n')
    self:write_file('frv_m104_stratagem.txt',
        table.concat(self.strat_lines, '\n\n') .. '\n')
    self:write_file('frv_m104_stratagem_dump.txt',
        table.concat(self.strat_dumps, '\n'))
    self:write_file('frv_m104_dump.txt', table.concat(self.dumps, '\n'))
    self:write_file('frv_m104_regions.txt', self.region_lines_cache or '')
    self.last_flush_frame = self.frame
end

-- ===========================================================================
-- 11. Entry point
-- ===========================================================================

function Recon.attach(self)
    local previous = update
    if type(previous) ~= 'function' then
        self.phase = 'failed'
        self.reason = 'global_update_missing'
        self:log(self.reason)
        self:flush()
        return false
    end
    local unpack_results = table.unpack or unpack
    local function pack_results(...) return { n = select('#', ...), ... } end
    -- 6.44: never break the update chain of mods loaded after us.
    local mine
    mine = function(...)
        local results = pack_results(previous(...))
        if not self.retired then
            self.frame = self.frame + 1
            if self.frame % Recon.STEP_EVERY == 0 then
                pcall(function() self:step() end)
            end
            if not self.finished
                and self.frame - self.last_flush_frame >= Recon.FLUSH_EVERY then
                pcall(function() self:flush() end)
            end
        end
        return unpack_results(results, 1, results.n)
    end
    update = mine
    self.retire_hook = function()
        self.retired = true
        if update == mine then update = previous end
    end
    rawset(_G, 'DshFrvM104ReconRetire', self.retire_hook)
    return true
end

if not rawget(_G, 'DshFrvM104ReconTest') then
    -- 6.19: assume this run fails.  Even a broken initialisation has to leave a
    -- file the user can send back, otherwise the only report is "nothing happened".
    local ok, instance = pcall(function() return Recon.new({}) end)
    if not ok then
        local reason = 'FAILED - init_failed: ' .. tostring(instance)
        pcall(function()
            local dir = Recon.default_dir()
            if not dir then return end
            local handle = io.open(dir .. '\\FRVM104Recon_STATUS.txt', 'w')
            if not handle then return end
            handle:write(reason .. '\naddon=' .. Recon.VERSION .. '\n')
            handle:close()
        end)
        pcall(function()
            if type(print) == 'function' then
                print('[FRVM104Recon] ' .. reason)
            end
        end)
    else
        instance:attach()
        pcall(function() instance:start() end)
    end
end

return Recon
