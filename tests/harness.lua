-- Offline harness for mods/dsh/frv_m104_recon.lua
--
-- The game is a LuaJIT process; the harness runs the addon under the same
-- runtime (lupa.luajit21) against a *fake* address space so the recon logic can
-- be exercised without a game session.  The stub is deliberately type-strict in
-- the places where the real Windows API is: an address that is not a number is
-- refused, a read that is not exactly representable is refused, and unreadable
-- pages return nil rather than empty data - the three ways a fake memory space
-- usually lies and lets a bug through.
--
-- Address space model: a list of {base, data} regions.  read() succeeds only
-- when one region covers [addr, addr+size) completely.

local M = {}

-- ---------------------------------------------------------------------------
-- byte helpers
-- ---------------------------------------------------------------------------
local function u32le(value)
    return string.char(value % 256,
        math.floor(value / 256) % 256,
        math.floor(value / 65536) % 256,
        math.floor(value / 16777216) % 256)
end

local function u64le(value)
    local lo = value % 4294967296
    local hi = math.floor(value / 4294967296) % 4294967296
    return u32le(lo) .. u32le(hi)
end

M.u32le, M.u64le = u32le, u64le

local function pad(text, size, filler)
    filler = filler or '\170'
    if #text < size then
        -- 6.3: never build byte strings with table.concat over numbers
        return text .. string.rep(filler, size - #text)
    end
    return text:sub(1, size)
end

local function poke(buffer, offset, text)
    if offset < 0 or offset + #text > #buffer then
        error(string.format('poke out of range: offset=%d len=%d buffer=%d',
            offset, #text, #buffer))
    end
    return buffer:sub(1, offset) .. text .. buffer:sub(offset + #text + 1)
end

M.pad, M.poke = pad, poke

function M.read_file(path)
    local handle = assert(io.open(path, 'rb'), 'cannot open ' .. tostring(path))
    local data = handle:read('*a')
    handle:close()
    return data
end

function M.hex(bytes)
    local parts = {}
    for i = 1, #bytes do parts[i] = string.format('%02x', string.byte(bytes, i)) end
    return table.concat(parts)
end

function M.hex_to_bytes(hex)
    return (hex:gsub('%x%x', function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

-- ---------------------------------------------------------------------------
-- fixtures
-- ---------------------------------------------------------------------------
M.ADDR = {
    big = 0x100000000,
    strat = 0x200000000,
    detached = 0x600000000,   -- nested arrays in their own allocation
    self = 0x100100000,      -- where the harness "finds" its own pattern strings
}

local STRAT_TYPE = 0x30eb6399
local SIGNATURE_HEX = '70cac1804c444c440100000070cac1809ecd0200'
local SIGNATURE = (SIGNATURE_HEX:gsub('%x%x', function(pair)
    return string.char(tonumber(pair, 16))
end))
local FRV_BASE = (('b9efebd3ffc721cc'):gsub('%x%x', function(pair)
    return string.char(tonumber(pair, 16))
end))
local FRV_SUPPLY = (('2e4340863740219b'):gsub('%x%x', function(pair)
    return string.char(tonumber(pair, 16))
end))
local FRV_HEAVY = (('e57f71d8e3bf852d'):gsub('%x%x', function(pair)
    return string.char(tonumber(pair, 16))
end))
local DELIVERY = (('b3a69285ed82be75'):gsub('%x%x', function(pair)
    return string.char(tonumber(pair, 16))
end))

M.SIGNATURE_HEX = SIGNATURE_HEX

-- Build a StratagemSettings LDLD instance image.
--   layout:  'abs'  descriptor holds an absolute pointer to a separate array
--            'rel'  descriptor holds a relative offset; array follows inline
--   count:   how many records the descriptor claims
--   placements: { { record = n, field = m, id = 'frv_base'|'frv_supply'|
--                   'frv_heavy'|'delivery' }, ... } written into the array.
--               When absent, `id_at` / `ref_at` build the usual shape.
--   nested:     { { record = n, id = ..., pointer_field = m }, ... } models the
--               REAL stratagem shape: the ids live in a nested array appended
--               after the records, reached through a pointer stored in the record.
--               `nested_relative` stores a relative offset instead of an absolute
--               address (the file form).  With this shape `(size-16)` deliberately
--               does NOT divide by the record count, exactly as the real table.
local ID_BYTES = {
    frv_base = FRV_BASE, frv_supply = FRV_SUPPLY, frv_heavy = FRV_HEAVY,
    delivery = DELIVERY,
}

-- ---------------------------------------------------------------------------
-- the asset package field (the other half of the pair)
-- ---------------------------------------------------------------------------
-- Live-measured, not assumed: the StratagemSettings `package` hash sits at record
-- +168, immediately after the 16-byte payload DLArray descriptor at +152.  That
-- was proven by matching the community plaintext dump to live memory by `id` -
-- for 70 of 100 records the community `package` value is exactly at +168.  The
-- game loads the stratagem's assets out of that package and every FRV variant
-- names its own, so patching only the vehicle asks for assets the record never
-- loads (the live game crashed on call-in doing exactly that).
--
-- The live table always carries the M-104 record beside the M-102 one, so a
-- fixture that plants an M-102 id plants the sibling M-104 record too and gives
-- each of them a package - unless `no_target_record` asks for the other case.
M.PACKAGE_FIELD = 168
M.PACKAGE_SIZE = 8
M.PACKAGE_BASE_HEX = '1111111111111111'
M.PACKAGE_TARGET_HEX = '2222222222222222'
local PACKAGE_BASE = M.hex_to_bytes(M.PACKAGE_BASE_HEX)
local PACKAGE_TARGET = M.hex_to_bytes(M.PACKAGE_TARGET_HEX)

local function make_strat_region(kind, base, copy_index)
    base = base or M.ADDR.strat
    copy_index = copy_index or 1
    local mag = base + 0x1000
    local stride = 312
    local count = kind.count or 8

    -- The sibling M-104 record, modelled before anything is sized.  A copy is
    -- built so the fixture table itself is never mutated (fixtures are shared
    -- between tests and a leak would make the suite order-dependent).
    local nested_entries = kind.nested
    if kind.nested then
        nested_entries = {}
        for index, entry in ipairs(kind.nested) do nested_entries[index] = entry end
        if not kind.no_target_record then
            local donor, has_heavy = nil, false
            for _, entry in ipairs(nested_entries) do
                if entry.id == 'frv_base' then donor = entry end
                if entry.id == 'frv_heavy' then has_heavy = true end
            end
            if donor and not has_heavy then
                local used = {}
                for _, entry in ipairs(nested_entries) do used[entry.record] = true end
                local free = nil
                for candidate = count - 1, 0, -1 do
                    if not used[candidate] then free = candidate break end
                end
                if free then
                    nested_entries[#nested_entries + 1] = {
                        record = free, id = 'frv_heavy',
                        pointer_field = donor.pointer_field,
                        elements = donor.elements,
                    }
                end
            end
        end
    end

    -- each nested entry gets a 32-byte block: the payload array plus padding
    local nested_bytes = kind.nested and not kind.nested_detached
        and (#nested_entries * 32) or 0
    local size = 16 + count * stride + (kind.size_bias or 0) + nested_bytes

    -- copy_placements lets a fixture give each copy of the table its own layout,
    -- which is the only way to build "the id sits at a different field offset in
    -- a different copy" - a single-copy fixture cannot express that
    local placements = (kind.copy_placements and kind.copy_placements[copy_index])
        or kind.placements
    if kind.nested and not placements then
        -- The nested shape puts the ids in appended arrays and NOT in the records.
        -- Without this, the id_at default below would ALSO plant the id inline in
        -- record 5, and a scale fixture (where the nested records are 100 and 110)
        -- then reports the id at two different field keys.  Modelling a shape half
        -- way is how a fixture lies.
        placements = {}
    end
    if not placements then
        local id_at = 5
        if kind.id_at ~= nil then id_at = kind.id_at end
        if kind.no_ids then id_at = count end
        placements = {}
        if id_at and id_at < count then
            placements[#placements + 1] = { record = id_at, field = 112, id = 'frv_base' }
            placements[#placements + 1] = { record = id_at, field = 120, id = 'delivery' }
        end
        if kind.ref_at and kind.ref_at < count and kind.ref_at ~= id_at then
            placements[#placements + 1] =
                { record = kind.ref_at, field = 112, id = 'frv_supply' }
        end
    end
    -- the sibling M-104 record really sits in this table: keep the fixtures honest
    if not kind.no_target_record then
        local heavy, donor = false, nil
        for _, placement in ipairs(placements) do
            if placement.id == 'frv_heavy' then heavy = true end
            if placement.id == 'frv_base' then donor = placement end
        end
        if donor and not heavy then
            local used = {}
            for _, placement in ipairs(placements) do used[placement.record] = true end
            local free = nil
            for candidate = count - 1, 0, -1 do
                if not used[candidate] then free = candidate break end
            end
            if free then
                placements[#placements + 1] =
                    { record = free, field = donor.field, id = 'frv_heavy' }
            end
        end
    end

    -- Realistic placement: in BOTH forms the records sit immediately after the
    -- 16-byte descriptor (that is what the file image looks like), and only the
    -- descriptor's first u64 differs - a relative offset 16 in the file, an absolute
    -- address in memory (skill 6.13).  Putting the array at an unrelated address
    -- would not model anything the game can produce, and would break the nested
    -- pointer filter, which only follows values that land inside the instance.
    local payload_start = mag + 24
    local array_addr = payload_start + 16
    local descriptor_value = (kind.layout == 'rel') and 16 or array_addr
    local header = u32le(STRAT_TYPE) .. 'LDLD' .. u32le(1) .. u32le(STRAT_TYPE)
        .. u32le(size) .. string.char(1) .. string.rep('\0', 7)
    local descriptor = u64le(descriptor_value) .. u64le(count)

    local region = pad('', 0x100000, '\170')
    region = poke(region, mag - 4 - base, header .. descriptor)

    -- Real records start with `type`, a StratagemType enum id, and the patcher uses
    -- that column to decide which stride hypothesis is worth searching.  A fixture
    -- of uniform filler bytes would score zero on every hypothesis, so the column is
    -- filled the way the game fills it, and the rest of each record gets a
    -- deterministic pseudo-random pattern rather than one repeated byte.
    local pieces = {}
    for index = 0, count - 1 do
        local record = {}
        for byte = 0, stride - 1 do
            record[byte + 1] = string.char((index * 37 + byte * 11 + 7) % 256)
        end
        record[1] = u32le(index + 1):sub(1, 1)
        record[2] = u32le(index + 1):sub(2, 2)
        record[3] = u32le(index + 1):sub(3, 3)
        record[4] = u32le(index + 1):sub(4, 4)
        if kind.garbage_types then
            -- a build whose record does not start with a small enum: every stride
            -- hypothesis then scores zero and the record scan is never attempted,
            -- which is exactly the case the whole-payload fallback exists for
            for byte = 0, 3 do
                record[byte + 1] = string.char((index * 37 + byte * 11 + 7) % 256)
            end
        end
        pieces[#pieces + 1] = table.concat(record)
    end
    local array = table.concat(pieces)
    for _, placement in ipairs(placements) do
        local bytes = ID_BYTES[placement.id]
        if bytes and placement.record < count then
            array = poke(array, placement.record * stride + (placement.field or 112),
                bytes)
        end
    end
    -- The nested shape: the ids are NOT in the records.  Each one gets its own
    -- 32-byte block appended after the records, and the owning record carries a
    -- pointer (or, in the file form, a relative offset) to it.
    local nested_base = array_addr + #array
    if kind.nested then
        local block = string.rep('\0', #nested_entries * 32)
        for index, entry in ipairs(nested_entries) do
            local at = (index - 1) * 32
            block = poke(block, at, ID_BYTES[entry.id] or FRV_BASE)
            -- `nested_detached` models the array living in its OWN allocation: the
            -- file image has to keep it inside the instance, but the runtime does
            -- not, and the record then simply holds an absolute pointer elsewhere
            local where = kind.nested_detached
                and (M.ADDR.detached + (copy_index - 1) * 0x10000 + at)
                or (nested_base + at)
            local stored = (kind.nested_relative and not kind.nested_detached)
                and (where - payload_start) or where
            local pointer_field = entry.pointer_field or 112
            array = poke(array, entry.record * stride + pointer_field, u64le(stored))
            -- a real DLArray is <u64 ptr, u64 count>; the count lets the patcher
            -- size its read so it does not run into the next record's array
            if not kind.no_nested_count then
                array = poke(array, entry.record * stride + pointer_field + 8,
                    u64le(entry.elements or 2))
            end
        end
        if not kind.nested_detached then
            array = array .. block
        end
    end
    -- Every record that names a vehicle also names the package its assets come
    -- from, so the fixture gives one to each side of the pair.
    local packages = {}
    local function note_package(record, id)
        if id == 'frv_base' then packages[record] = PACKAGE_BASE end
        if id == 'frv_heavy' then packages[record] = PACKAGE_TARGET end
    end
    for _, placement in ipairs(placements) do
        note_package(placement.record, placement.id)
    end
    if kind.nested then
        for _, entry in ipairs(nested_entries) do
            note_package(entry.record, entry.id)
        end
    end
    for record, value in pairs(packages) do
        array = poke(array, record * stride + M.PACKAGE_FIELD, value)
    end
    region = poke(region, array_addr - base, array)

    return { base = base, data = region, array_addr = array_addr,
             count = count, stride = stride, mag = mag, size = size,
             nested_base = nested_base, placements = placements,
             -- what the nested shape actually used, sibling entry included, so the
             -- detached-allocation copy can lay out the very same block
             nested_entries = nested_entries,
             packages = packages }
end

function M.build(kind)
    kind = kind or {}
    local regions = {}

    -- the "big" region: entity blob signature plus decoys
    local big = pad('', 0x400000, '\153')
    big = poke(big, 0x12345, SIGNATURE)
    -- decoy: a copy of the ids somewhere unrelated, to prove classification
    big = poke(big, 0x30000, FRV_BASE .. DELIVERY)
    -- self-detection bait: the scanner's own pattern strings live on the Lua
    -- heap, so a real sweep WILL find them.  Put them at the address the fake
    -- api.string_address() reports and check they are skipped (6.2).
    if kind.self_addr then
        big = poke(big, kind.self_addr - M.ADDR.big,
            FRV_BASE .. DELIVERY .. SIGNATURE)
    end
    regions[#regions + 1] = { base = M.ADDR.big, data = big }

    -- raw_regions inject a byte image from disk - used to run the addon against a
    -- REAL game table (read out of the plaintext mirror) instead of a synthetic
    -- one.  The path must be ASCII: Lua's fopen cannot open a path with non-ASCII
    -- characters in it (a documented lupa/Windows trap).
    for _, raw in ipairs(kind.raw_regions or {}) do
        regions[#regions + 1] = { base = raw.base, data = M.read_file(raw.path) }
    end

    if kind.no_strat then
        return { regions = regions, regions_phase2 = {},
                 self_texts = kind.self_texts or {}, self_addr = kind.self_addr }
    end

    local strat = make_strat_region(kind)
    -- `strat_in_phase2` models a table that only a mission load brings in: sweep 1
    -- sees the small address space, later sweeps see the stratagem table plus a
    -- handful of extra regions (which is what the reload heuristic keys on).
    local phase2 = {}
    if kind.strat_in_phase2 then
        for i = 1, (kind.extra_regions or 6) do
            phase2[#phase2 + 1] = { base = 0x300000000 + i * 0x200000,
                                    data = pad('', 0x100000, '\170') }
        end
        phase2[#phase2 + 1] = { base = strat.base, data = strat.data }
    else
        regions[#regions + 1] = { base = strat.base, data = strat.data }
    end
    -- extra copies of the same table: the real game keeps dozens and reloads them,
    -- so "patch one copy" is the standard cause of "worked, then stopped"
    local copies = { strat }
    local late = {}
    for i = 1, (kind.extra_copies or 0) do
        local more = make_strat_region(kind, M.ADDR.strat + i * 0x40000000, i + 1)
        regions[#regions + 1] = { base = more.base, data = more.data }
        copies[#copies + 1] = more
    end
    if kind.read_only then
        -- a read-only page is what the kernel refuses to write; the addon relies
        -- on that refusal instead of calling VirtualProtect
        for _, region in ipairs(regions) do region.read_only = true end
    end
    if kind.nested_detached then
        -- the allocation the records point at, outside the instance payload
        local data = pad('', 0x10000, '\0')
        for index, entry in ipairs(strat.nested_entries or kind.nested) do
            data = poke(data, (index - 1) * 32, ID_BYTES[entry.id] or FRV_BASE)
        end
        regions[#regions + 1] = { base = M.ADDR.detached, data = data }
    end
    -- A mission load brings its OWN copies of the table: the copies patched on the
    -- ship become stale and the mission spawns the unpatched vehicle (measured
    -- 2026-09-25: the ship copy still read back as ours for the whole session while
    -- the mission delivered the M-102).  These copies only exist from the second
    -- regions() call on, so the addon can only find them by noticing the address
    -- space grew and sweeping the delta.
    for i = 1, (kind.late_copies or 0) do
        local more = make_strat_region(kind,
            M.ADDR.strat + 0x100000000 + i * 0x40000000, i + 1)
        phase2[#phase2 + 1] = { base = more.base, data = more.data }
        copies[#copies + 1] = more
        late[#late + 1] = more
    end
    if kind.late_copies then
        -- a real level load more than doubles resident memory; the follower's gate
        -- is a real growth jump (not "some new regions appeared"), so the fixture
        -- has to actually grow like one
        for i = 1, (kind.late_regions or 2) do
            phase2[#phase2 + 1] = { base = 0x400000000 + i * 0x200000,
                                    data = pad('', 0x100000, '\170') }
        end
    end
    -- Later waves model ordinary churn: a handful of new regions and no level load.
    -- The follower must NOT re-scan for those.  Live measurement: the first, looser
    -- gate fired 14 times in 8 minutes - on a pass where the address space had even
    -- SHRUNK - and each pass re-scanned hundreds of MB for nothing.
    local waves = { phase2 }
    for w = 1, (kind.churn_waves or 0) do
        local wave = {}
        -- small on purpose: a few percent of resident memory, which is what ordinary
        -- streaming churn looks like next to a level load that adds 10%+ at once
        for i = 1, (kind.churn_regions or 1) do
            wave[#wave + 1] = { base = 0x500000000 + (w * 16 + i) * 0x200000,
                                data = pad('', (kind.churn_size or 0x80000), '\171') }
        end
        waves[#waves + 1] = wave
    end
    local flattened = {}
    for _, wave in ipairs(waves) do
        for _, region in ipairs(wave) do flattened[#flattened + 1] = region end
    end
    return { regions = regions, regions_phase2 = flattened, waves = waves,
             strat = strat, copies = copies, late = late,
             -- flags the fake api keys off must survive into the fixture
             lying_writer = kind.lying_writer,
             self_texts = kind.self_texts or {}, self_addr = kind.self_addr }
end

-- ---------------------------------------------------------------------------
-- fake api
-- ---------------------------------------------------------------------------
function M.api(fixture)
    local api = { name = 'fake', ffi = nil }
    local t = 0
    local region_calls = 0
    -- `read` must know every region the address space can ever expose, not just
    -- the ones the first regions() call returned - otherwise the phase-2 fixture
    -- silently reads as unmapped and the sweep "scans" bytes it never sees
    local known = {}
    for _, region in ipairs(fixture.regions) do known[#known + 1] = region end
    for _, region in ipairs(fixture.regions_phase2 or {}) do
        known[#known + 1] = region
    end
    local self_map = {}
    for _, text in ipairs(fixture.self_texts or {}) do
        self_map[text] = fixture.self_addr
    end

    function api.time()
        t = t + 5          -- collapse the sweep backoff into a few iterations
        return t
    end

    function api.regions(min_size)
        region_calls = region_calls + 1
        -- phase 1 is what the game looks like at first; every later regions() call
        -- reveals one more wave, so "a level load" and "ordinary churn" are two
        -- different shapes rather than one big reveal
        local source = {}
        for _, region in ipairs(fixture.regions) do
            source[#source + 1] = region
        end
        local waves = fixture.waves or {}
        for w = 1, math.min(region_calls - 1, #waves) do
            for _, region in ipairs(waves[w]) do
                source[#source + 1] = region
            end
        end
        local list = {}
        for _, region in ipairs(source) do
            if #region.data >= (min_size or 0) then
                list[#list + 1] = { base = region.base, size = #region.data,
                                    protect = 0x04 }
            end
        end
        table.sort(list, function(a, b)
            -- mirrors the addon: smallest first, because the settings tables live in
            -- ordinary small heap regions rather than in the multi-MB asset blocks
            if a.size == b.size then return a.base < b.base end
            return a.size < b.size
        end)
        return list
    end

    function api.read(address, size)
        -- 6.4: only a real number is an address; a string must not silently
        -- become one, or the harness would pass where the game raises
        if type(address) ~= 'number' then
            error('read() address is ' .. type(address) .. ', expected number')
        end
        if type(size) ~= 'number' or size <= 0 then
            error('read() size is ' .. tostring(size))
        end
        if address < 65536 then return nil end
        for _, region in ipairs(known) do
            if address >= region.base and address + size <= region.base + #region.data then
                local from = address - region.base
                return region.data:sub(from + 1, from + size)
            end
        end
        return nil
    end

    function api.string_address(text)
        return self_map[text]
    end

    function api.module(name)
        return nil
    end

    -- ---- write path (only the v2 addon uses it) -----------------------------
    -- Writing into a region marked read_only fails, which is how the real
    -- Windows API behaves for a code page and is exactly the guarantee the addon
    -- relies on instead of calling VirtualProtect.
    local writes = {}
    local function region_at(address, size)
        for _, region in ipairs(known) do
            if address >= region.base
                and address + size <= region.base + #region.data then
                return region
            end
        end
        return nil
    end

    -- A write that reports success without changing anything.  `true` lies about
    -- every write; 'package' / 'vehicle' lie only about that half of the pair, so
    -- each read-back can be shown to be load-bearing on its own - with both tied
    -- together, an untargeted liar is caught by whichever check runs first and the
    -- other one could be deleted without the suite noticing.
    local function is_package_slot(address)
        local strat = fixture.strat
        if not strat or not strat.array_addr then return false end
        local delta = address - strat.array_addr - M.PACKAGE_FIELD
        return delta >= 0 and delta % strat.stride == 0
    end

    function api.write(address, bytes)
        if type(address) ~= 'number' then
            error('write() address is ' .. type(address) .. ', expected number')
        end
        if type(bytes) ~= 'string' or #bytes == 0 then
            error('write() bytes must be a non-empty string')
        end
        local region = region_at(address, #bytes)
        if region == nil then
            writes[#writes + 1] = { address = address, bytes = bytes, ok = false,
                                    why = 'unmapped' }
            return false, 'unmapped'
        end
        if region.read_only then
            writes[#writes + 1] = { address = address, bytes = bytes, ok = false,
                                    why = 'read_only' }
            return false, 'read_only'
        end
        local lie = fixture.lying_writer
        if lie == true or (lie == 'package' and is_package_slot(address))
            or (lie == 'vehicle' and not is_package_slot(address)) then
            -- a writer that reports success without changing anything: the addon
            -- must notice via its read-back, not trust the return value
            writes[#writes + 1] = { address = address, bytes = bytes, ok = true,
                                    lied = true }
            return true
        end
        local from = address - region.base
        region.data = region.data:sub(1, from) .. bytes
            .. region.data:sub(from + #bytes + 1)
        writes[#writes + 1] = { address = address, bytes = bytes, ok = true }
        return true
    end

    -- test instrumentation: change memory behind the addon's back, to model the
    -- game reloading a copy or another mod owning the field
    function api.poke(address, bytes)
        local region = assert(region_at(address, #bytes), 'poke outside a region')
        local from = address - region.base
        region.data = region.data:sub(1, from) .. bytes
            .. region.data:sub(from + #bytes + 1)
    end

    api.writes = writes
    api.region_at = region_at

    return api
end

-- ---------------------------------------------------------------------------
-- driving the addon
-- ---------------------------------------------------------------------------
-- `Recon` is injected by the caller (run_tests*.py loads the real addon source).
-- `opts.on_frame(instance, api)` is called after every step, so a test can poke
-- memory (model a reload) or record state while the loop is still running.
function M.run(Recon, kind, opts)
    opts = opts or {}
    local fixture = M.build(kind)
    local api = M.api(fixture)
    local config = opts.config
    local instance = Recon.new({
        api = api,
        dir = false,                       -- never write to the real %LOCALAPPDATA%
        emit = opts.emit or function() end,
        config = config,
        verify_interval = opts.verify_interval or 0.001,
    })
    instance:start()
    local frames = opts.frames or 3000
    for frame = 1, frames do
        instance.frame = frame
        instance:step()
        if opts.on_frame then pcall(opts.on_frame, instance, api) end
        if instance.finished then break end
    end
    local write_ok, write_failed = 0, 0
    for _, entry in ipairs(api.writes) do
        if entry.ok then write_ok = write_ok + 1 else write_failed = write_failed + 1 end
    end
    -- the harness drives both the read-only v1 addon and the v2 patcher, so every
    -- v2-only accessor is optional
    local function optional(method, ...)
        if type(instance[method]) ~= 'function' then return nil end
        local ok, value = pcall(instance[method], instance, ...)
        if not ok then return nil end
        return value
    end
    local patch_report = optional('patch_lines')
    local originals = optional('originals_lines')
    local restore_count = optional('restore_all') or 0
    local after = {}
    for index, target in ipairs(instance.patch_targets or {}) do
        local now = api.read(target.address, 8)
        after[index] = now and M.hex(now) or 'nil'
    end
    -- the package half of the pair: where it was written and what it holds now
    local packages_after = {}
    for index, entry in ipairs(instance.package_targets or {}) do
        local now = entry.address and api.read(entry.address, M.PACKAGE_SIZE)
        packages_after[index] = now and M.hex(now) or 'nil'
    end
    return {
        phase = instance.phase,
        reason = instance.reason,
        finished = instance.finished,
        record_hits = instance.record_hits,
        strat_count = #instance.strat_instances,
        strat_lines = table.concat(instance.strat_lines, '\n\n'),
        strat_dumps = table.concat(instance.strat_dumps, '\n'),
        hit_lines = table.concat(instance.hit_lines, '\n'),
        census = instance.census_count,
        census_lines = table.concat(instance.census_lines, '\n'),
        sweeps = instance.sweeps,
        self_hits = instance.self_hits,
        level_loads = instance.level_loads,
        log_lines = table.concat(instance.log_lines, '\n'),
        region_lines = instance.region_lines_cache or '',
        status = instance:status_text(),
        patch_report = patch_report and table.concat(patch_report, '\n') or '',
        originals = originals and table.concat(originals, '\n') or '',
        -- patch state
        stride = instance.stride,
        patch_state = instance.patch_state,
        patch_field = instance.patch_field,
        patch_field_key = instance.patch_field_key,
        patch_confidence = instance.patch_confidence,
        patch_reason = instance.patch_reason,
        patched_count = instance.patched_count,
        refused_count = instance.refused_count,
        reapplied_count = instance.reapplied_count,
        foreign_count = instance.foreign_count,
        rescans = instance.rescans,
        targets = instance.targets,
        patch_targets = instance.patch_targets,
        package_targets = instance.package_targets,
        packages_after = table.concat(packages_after, ','),
        package_swapped = instance.package_written or 0,
        package_refused = instance.package_refused or 0,
        follows = instance.follows or 0,
        observed = instance.observed,
        restore = restore_count,
        after_restore = table.concat(after, ','),
        after_restore_count = #after,
        write_ok = write_ok,
        write_failed = write_failed,
        writes = api.writes,
        fixture = fixture,
        instance = instance,
    }
end

return M
