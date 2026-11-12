"""Küçük QR kod üreteci (ISO/IEC 18004): bayt kipi, hata düzeltme seviyesi M, sürüm 1-10.

İki adımlı doğrulama kurulumundaki otpauth:// adresini göstermek için yeterlidir (en fazla 213 bayt).
Üçüncü taraf kitaplık kullanılmaz. `encode(text)` kare bir 0/1 matrisi döndürür (1 = koyu modül)."""

# Sürüm -> (blok başına hata düzeltme baytı, [(blok sayısı, bloktaki veri baytı), ...]) — seviye M
BLOCKS = {
    1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
    6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}
ALIGNMENT = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
             7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0, lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]

# GF(256) üs/logaritma tabloları (ilkel polinom 0x11D)
_EXP, _LOG = [0] * 512, [0] * 256
_value = 1
for _i in range(255):
    _EXP[_i], _LOG[_value] = _value, _i
    _value <<= 1
    if _value & 0x100:
        _value ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def rs_remainder(data, degree):
    """Reed-Solomon hata düzeltme baytları: data(x)·x^degree'nin üreteç polinomuna bölümünden kalan."""
    generator = [1]
    for i in range(degree):          # (x - α^0)(x - α^1)...(x - α^(degree-1)); en yüksek dereceli katsayı başta
        generator = _poly_mul(generator, [1, _EXP[i]])
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        for j in range(degree):
            remainder[j] ^= _gf_mul(generator[j + 1], factor)
    return remainder


def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] ^= _gf_mul(x, y)
    return out


def capacity(version):
    """Sürümün bayt kipinde taşıyabildiği en fazla bayt."""
    data_codewords = sum(count * size for count, size in BLOCKS[version][1])
    return data_codewords - (2 if version <= 9 else 3)


def _codewords(payload, version):
    """Veri bit dizisini kurar, bloklara böler, hata düzeltmeyi ekler ve serpiştirir."""
    ec_len, groups = BLOCKS[version]
    total_data = sum(count * size for count, size in groups)
    bits = [0, 1, 0, 0]                                             # bayt kipi
    length_bits = 8 if version <= 9 else 16
    bits += [(len(payload) >> i) & 1 for i in range(length_bits - 1, -1, -1)]
    for byte in payload:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, total_data * 8 - len(bits))                 # sonlandırıcı
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    for pad in range(total_data - len(data)):
        data.append(0xEC if pad % 2 == 0 else 0x11)

    blocks, offset = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(data[offset:offset + size])
            offset += size
    ec_blocks = [rs_remainder(block, ec_len) for block in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):                     # veri baytları sütun sütun
        out += [b[i] for b in blocks if i < len(b)]
    for i in range(ec_len):
        out += [b[i] for b in ec_blocks]
    return out


def _bch(value, generator, shift):
    remainder = value << shift
    top = generator.bit_length() - 1
    for bit in range(remainder.bit_length() - 1, top - 1, -1):
        if remainder >> bit & 1:
            remainder ^= generator << (bit - top)
    return (value << shift) | remainder


def _function_patterns(version):
    """(matris, işlev modülü haritası): bulucu, hizalama ve zamanlama desenleri; biçim/sürüm alanları ayrılır."""
    size = version * 4 + 17
    grid = [[0] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        if 0 <= x < size and 0 <= y < size:
            grid[y][x], reserved[y][x] = 1 if dark else 0, True

    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):            # bulucular + ayırıcılar
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                distance = max(abs(dx), abs(dy))
                put(cx + dx, cy + dy, distance != 2 and distance != 4)
    centers = ALIGNMENT[version]
    for cy in centers:                                               # hizalama desenleri
        for cx in centers:
            if (cx, cy) in ((6, 6), (6, centers[-1]), (centers[-1], 6)):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)
    for i in range(8, size - 8):                                     # zamanlama desenleri
        put(i, 6, i % 2 == 0)
        put(6, i, i % 2 == 0)
    for i in range(9):                                               # biçim bilgisi alanları
        if not reserved[8][i]:
            put(i, 8, False)
        if not reserved[i][8]:
            put(8, i, False)
    for i in range(8):
        put(size - 1 - i, 8, False)
        put(8, size - 1 - i, False)
    put(8, size - 8, True)                                           # sabit koyu modül
    if version >= 7:                                                 # sürüm bilgisi
        bits = _bch(version, 0x1F25, 12)
        for i in range(18):
            dark = bits >> i & 1
            a, b = size - 11 + i % 3, i // 3
            put(a, b, dark)
            put(b, a, dark)
    return grid, reserved


def _place_data(grid, reserved, codewords):
    size = len(grid)
    bits = [(byte >> i) & 1 for byte in codewords for i in range(7, -1, -1)]
    index, right = 0, size - 1
    while right >= 1:                                                # sağdan sola iki sütunluk şeritler
        if right == 6:                                               # dikey zamanlama sütunu atlanır
            right = 5
        upward = ((right + 1) & 2) == 0
        for step in range(size):
            y = size - 1 - step if upward else step
            for x in (right, right - 1):
                if not reserved[y][x]:
                    grid[y][x] = bits[index] if index < len(bits) else 0   # artan modüller 0 kalır
                    index += 1
        right -= 2


def _write_format(grid, mask):
    size = len(grid)
    bits = _bch(mask, 0x537, 10) ^ 0x5412                            # seviye M'nin iki biti 00'dır
    bit = lambda i: bits >> i & 1
    for i in range(6):
        grid[i][8] = bit(i)
    grid[7][8], grid[8][8], grid[8][7] = bit(6), bit(7), bit(8)
    for i in range(9, 15):
        grid[8][14 - i] = bit(i)
    for i in range(8):
        grid[8][size - 1 - i] = bit(i)
    for i in range(8, 15):
        grid[size - 15 + i][8] = bit(i)


def _penalty(grid):
    size = len(grid)
    score = 0
    lines = grid + [list(col) for col in zip(*grid)]
    for line in lines:                                               # kural 1: aynı renkte 5+ modül
        run = 1
        for i in range(1, size + 1):
            if i < size and line[i] == line[i - 1]:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
        text = "".join(map(str, line))                               # kural 3: bulucuya benzeyen desen
        for pattern in ("10111010000", "00001011101"):
            start = text.find(pattern)
            while start != -1:
                score += 40
                start = text.find(pattern, start + 1)
    for y in range(size - 1):                                        # kural 2: 2x2 bloklar
        for x in range(size - 1):
            if grid[y][x] == grid[y][x + 1] == grid[y + 1][x] == grid[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, grid))                                       # kural 4: koyu/açık dengesi
    score += int(abs(dark * 20 - size * size * 10) / (size * size)) * 10
    return score


def encode(text, mask=None):
    """Metni QR matrisine çevirir. mask verilmezse ceza puanı en düşük maske seçilir."""
    payload = text.encode("utf-8")
    version = next((v for v in sorted(BLOCKS) if len(payload) <= capacity(v)), None)
    if version is None:
        raise ValueError("Metin QR kod için çok uzun.")
    base, reserved = _function_patterns(version)
    _place_data(base, reserved, _codewords(payload, version))
    best = None
    for candidate in ([mask] if mask is not None else range(8)):
        grid = [[cell ^ (1 if not reserved[y][x] and MASKS[candidate](x, y) else 0) for x, cell in enumerate(row)]
                for y, row in enumerate(base)]
        _write_format(grid, candidate)
        score = _penalty(grid)
        if best is None or score < best[0]:
            best = (score, grid)
    return best[1]
