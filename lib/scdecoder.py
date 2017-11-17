import json
import os

from io import BytesIO


def read_byte(content):
    return int(content[:2], 16)


def read_short(content):
    return int(content[:4], 16)


def read_int(content):
    try:
        t = content[:8]
        if t == "FFFFFFFF":
            return 0
        else:
            return int(t, 16)
    except:
        return -1


def read_long(content):
    return int(content[:16], 16)


def read_rrsint32(content):
    bt = bytearray.fromhex(content)
    r = decode_stream(BytesIO(bt))
    b = r["r"]
    rrsint32 = ((b >> 1) ^ (-(b & 1)))
    r["r"] = rrsint32
    return r


def decode_stream(stream):
    shift = 0
    result = 0
    l = 0
    while True:
        byte = read_one(stream)
        l = l + 1
        if shift == 0:
            byte = seven_bit_rotate_left(byte)
        i = ord(byte)
        result |= (i & 0x7f) << shift
        shift += 7
        if not (i & 0x80):
            break

    return {"r": result, "len": l}


def read_one(stream):
    c = stream.read(1)
    if c == '':
        raise EOFError("Unexpected EOF while reading bytes")
    return c


def seven_bit_rotate_left(byte):
    n = int.from_bytes(byte, byteorder='big')
    seventh = (n & 0x40) >> 6  # save 7th bit
    msb = (n & 0x80) >> 7  # save msb
    n = n << 1  # rotate to the left
    n = n & ~0x181  # clear 8th and 1st bit and 9th if any
    n = n | (msb << 7) | seventh  # insert msb and 6th back in
    return bytes([n])


def seven_bit_rotate_right(byte):
    n = int.from_bytes(byte, byteorder='big')
    lsb = n & 0x1  # save lsb
    msb = (n & 0x80) >> 7  # save msb
    n = n >> 1  # rotate to the right
    n = n & ~0xC0  # clear 7th and 6th bit
    n = n | (msb << 7) | (lsb << 6)  # insert msb and lsb back in
    return bytes([n])


def decode(msg_id, hex_content, debug):
    definition_path = "definitions/" + str(msg_id) + ".json"
    result = {
        "messageId": msg_id
    }

    if not os.path.isfile(definition_path):
        result["result"] = "definition missing"
        if debug:
            result["remaining"]: hex_content
        return result

    definition = json.load(open(definition_path))
    return decode_def(result, hex_content, definition, debug, False)["result"]


def decode_def(result, hex_content, definition, debug, sub):
    unk = 0
    init_len = len(hex_content)

    for field in definition:
        field_type = field["type"]
        if "name" in field:
            field_name = field["name"]
        else:
            field_name = "unknown_" + str(unk)
            unk = unk + 1

        if field_type == 'BYTE':
            r = read_byte(hex_content)
            hex_content = hex_content[2:]
        elif field_type == 'SHORT':
            r = read_short(hex_content)
            hex_content = hex_content[4:]
        elif field_type == 'BOOLEAN':
            r = read_byte(hex_content) > 0
            hex_content = hex_content[2:]
        elif field_type == 'INT':
            r = read_int(hex_content)
            hex_content = hex_content[8:]
        elif field_type == 'LONG':
            r = read_long(hex_content)
            hex_content = hex_content[16:]
        elif field_type == 'RRSINT32':
            rrsint = read_rrsint32(hex_content)
            hex_content = hex_content[rrsint["len"] * 2:]
            r = rrsint["r"]
        elif field_type == 'RRSLONG':
            low = read_rrsint32(hex_content)
            hex_content = hex_content[low["len"] * 2:]
            high = read_rrsint32(hex_content)
            hex_content = hex_content[high["len"] * 2:]
            r = {
                "low": low["r"],
                "high": high["r"]
            }
        elif field_type == 'STRING':
            string_len = read_int(hex_content) * 2
            if string_len > -1:
                hex_content = hex_content[8:]
                r = bytearray.fromhex(hex_content[:string_len]).decode()
                hex_content = hex_content[string_len:]
            else:
                r = "Failed to parse string"
                result[field_name] = r
                break
        elif field_type == 'SCID':
            high = read_rrsint32(hex_content)
            if high["r"] > 0:
                hex_content = hex_content[high["len"] * 2:]
                low = read_rrsint32(hex_content)
                hex_content = hex_content[low["len"] * 2:]
                r = high["r"] * 1000000 + low["r"]
            else:
                r = "Failed to parse SCID"
                result[field_name] = r
                break
        elif field_type == 'ARRAY':
            arr_len = read_byte(hex_content)
            hex_content = hex_content[2:]
            arr_component = field["component"]
            r = []
            for i in range(0, arr_len):
                arr_result = {}
                sub = decode_def(arr_result, hex_content, arr_component, debug, True)
                r.append(sub["result"])
                hex_content = hex_content[sub["len"]:]
        elif field_type == 'IGNORE':
            return {
                "result": result,
                "len": init_len - len(hex_content)
            }

        else:
            r = "Unknown type"
            result[field_name] = r
            break

        result[field_name] = r

    if len(hex_content) > 0 and debug and not sub:
        result["remaining"] = hex_content

    return {
        "result": result,
        "len": init_len - len(hex_content)
    }
