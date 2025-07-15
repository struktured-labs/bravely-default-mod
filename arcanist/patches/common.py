import json


def reserve_empty_region(
    *,
    regions: str,
    used_by: str | None = None,
    len: int | None = None,
    disable_region_reserve: bool = False,
) -> int:
    empty_regions = json.load(open(regions))

    def parse_addr(region: dict[str, str | int]) -> int:
        addr = region.get("addr")
        if not addr:
            raise ValueError("Region does not have an 'addr' field")
        return int(f"0x{addr}", 16)

    for i, region in enumerate(empty_regions):
        print(f"region: {region}")
        if region_used_by := region.get("used_by"):
            if used_by and used_by == region_used_by:
                return parse_addr(region)
            print(f"Empty region {i} at {region['addr']} is used by {region_used_by}.")
            continue
        elif (region_len := region.get("len", 0)) >= (len or 0):
            print(
                f"Empty region {i} at {region['addr']} with length {region_len} is not used by anything"
            )
            if used_by:
                region["used_by"] = used_by
                if not disable_region_reserve:
                    with open(regions, "w") as f:
                        json.dump(empty_regions, f, indent=4)
            return parse_addr(region)
        else:
            print(
                f"Empty region {i} at {region['addr']} with length {region_len} is not long enough (at least {len} bytes)"
            )

    raise ValueError("No empty region found in file ../data/empty_regions.json")
