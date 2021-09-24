CREATE OR REPLACE FUNCTION parse_ulid(ulid text) RETURNS bytea AS $$
DECLARE
  bytes bytea = E'\\x00000000000000000000000000000000';
  v     char[];
  -- Allow for O(1) lookup of index values
  dec   integer[] = ARRAY[
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'00'::int, x'01'::int, x'02'::int,
    x'03'::int, x'04'::int, x'05'::int, x'06'::int, x'07'::int, x'08'::int, x'09'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'0A'::int, x'0B'::int, x'0C'::int, x'0D'::int, x'0E'::int, x'0F'::int,
    x'10'::int, x'11'::int, x'FF'::int, x'12'::int, x'13'::int, x'FF'::int, x'14'::int, x'15'::int, x'FF'::int, x'16'::int,
    x'17'::int, x'18'::int, x'19'::int, x'1A'::int, x'FF'::int, x'1B'::int, x'1C'::int, x'1D'::int, x'1E'::int, x'1F'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'0A'::int, x'0B'::int, x'0C'::int, x'0D'::int,
    x'0E'::int, x'0F'::int, x'10'::int, x'11'::int, x'FF'::int, x'12'::int, x'13'::int, x'FF'::int, x'14'::int, x'15'::int,
    x'FF'::int, x'16'::int, x'17'::int, x'18'::int, x'19'::int, x'1A'::int, x'FF'::int, x'1B'::int, x'1C'::int, x'1D'::int,
    x'1E'::int, x'1F'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int,
    x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int, x'FF'::int
  ];
BEGIN
  ulid = upper(ulid);

  IF NOT ulid ~ '^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$' THEN
    RAISE EXCEPTION 'Invalid ULID: %', ulid;
  END IF;

  v = regexp_split_to_array(ulid, '');

  -- 6 bytes timestamp (48 bits)
  bytes = SET_BYTE(bytes, 0, (dec[ASCII(v[1])] << 5) | dec[ASCII(v[2])]);
  bytes = SET_BYTE(bytes, 1, (dec[ASCII(v[3])] << 3) | (dec[ASCII(v[4])] >> 2));
	bytes = SET_BYTE(bytes, 2, (dec[ASCII(v[4])] << 6) | (dec[ASCII(v[5])] << 1) | (dec[ASCII(v[6])] >> 4));
	bytes = SET_BYTE(bytes, 3, (dec[ASCII(v[6])] << 4) | (dec[ASCII(v[7])] >> 1));
	bytes = SET_BYTE(bytes, 4, (dec[ASCII(v[7])] << 7) | (dec[ASCII(v[8])] << 2) | (dec[ASCII(v[9])] >> 3));
	bytes = SET_BYTE(bytes, 5, (dec[ASCII(v[9])] << 5) | dec[ASCII(v[10])]);

	-- 10 bytes of entropy (80 bits);
	bytes = SET_BYTE(bytes, 6, (dec[ASCII(v[11])] << 3) | (dec[ASCII(v[12])] >> 2));
	bytes = SET_BYTE(bytes, 7, (dec[ASCII(v[12])] << 6) | (dec[ASCII(v[13])] << 1) | (dec[ASCII(v[14])] >> 4));
	bytes = SET_BYTE(bytes, 8, (dec[ASCII(v[14])] << 4) | (dec[ASCII(v[15])] >> 1));
	bytes = SET_BYTE(bytes, 9, (dec[ASCII(v[15])] << 7) | (dec[ASCII(v[16])] << 2) | (dec[ASCII(v[17])] >> 3));
	bytes = SET_BYTE(bytes, 10, (dec[ASCII(v[17])] << 5) | dec[ASCII(v[18])]);
	bytes = SET_BYTE(bytes, 11, (dec[ASCII(v[19])] << 3) | (dec[ASCII(v[20])] >> 2));
	bytes = SET_BYTE(bytes, 12, (dec[ASCII(v[20])] << 6) | (dec[ASCII(v[21])] << 1) | (dec[ASCII(v[22])] >> 4));
	bytes = SET_BYTE(bytes, 13, (dec[ASCII(v[22])] << 4) | (dec[ASCII(v[23])] >> 1));
	bytes = SET_BYTE(bytes, 14, (dec[ASCII(v[23])] << 7) | (dec[ASCII(v[24])] << 2) | (dec[ASCII(v[25])] >> 3));
	bytes = SET_BYTE(bytes, 15, (dec[ASCII(v[25])] << 5) | dec[ASCII(v[26])]);

  RETURN bytes;
END
$$
LANGUAGE plpgsql
IMMUTABLE;


CREATE OR REPLACE FUNCTION ulid_to_uuid(ulid text) RETURNS uuid AS $$
BEGIN
  RETURN encode(parse_ulid(ulid), 'hex')::uuid;
END
$$
LANGUAGE plpgsql
IMMUTABLE;