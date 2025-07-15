import pandas as pd
import numpy as np
from typing import Mapping, Sequence
from functools import lru_cache
from collections.abc import Iterable
import pathlib


# Design idea:
# Most functions return a dataframe.
# User can load a file to make a dateframe
# User can edit the dataframe, and save it back to a file.
# Perhaps high level functions can be used to load a file, edit it, and save it back
# Consider a data file to reprsent edits (e.g. a file with columns like "file", "row", "col", "value")

type CrowdData = dict[str, pd.DataFrame]


@lru_cache
def _load_all(file: str) -> CrowdData:
    match pd.read_excel(file, sheet_name=None):  # type: ignore
        case dict() as sheets:
            return sheets
        case _:
            raise ValueError(
                f"File {file} does not contain any sheets or is not a valid vrecrowd excel file."
            )


def _maybe_load_all(file_or_df: str | CrowdData) -> CrowdData:
    match file_or_df:
        case str() as file:
            file = pathlib.Path(file)
            if file.is_dir():
                file = file / "crowd.xls"            
            return _load_all(file) 
        case dict() as crowd_data:
            return crowd_data
        case _:
            raise ValueError(f"Unexpected input: {file_or_df}")


def load(file: CrowdData | str, pat: str | None = None) -> CrowdData:
    """Load datasets from a file or a dictionary of datasets, filtering by a pattern.
    Args:
        file (str or CrowdData): The file path or a dictionary of datasets.
        pat (str): The pattern to filter datasets by.
    Returns:
        CrowdData: A dictionary of datasets that match the pattern.
    """

    if pat is None:

        def predicate(txt: str) -> bool:
            del txt
            return True

    else:

        def predicate(txt: str) -> bool:
            return pat.lower() in txt.lower()

    ds = _maybe_load_all(file)
    datasets: CrowdData = {}
    for key in ds.keys():
        dss = ds[key]
        if predicate(key):
            datasets[key] = dss
            continue
        col_names: Iterable[str] = dss.keys()  # type: ignore
        for col in col_names:  # type: ignore
            assert isinstance(
                col, str
            ), f"Column name {col} in dataset {key} is not a string."
            print(f"check col {key}/{col}")
            if predicate(col) or (dss[col].dtype.kind in ["S", "U"] and np.any(dss[col].str.contains(text))):  # type: ignore
                datasets[key] = dss
                break

    return datasets


from dataclasses import dataclass
from dataclasses import field

@dataclass(frozen=True)
class CrowdSchema:
    sheet: str
    index: Mapping[int, str] = field(default_factory=lambda: dict[int, str]())
    columns: Mapping[int, str] = field(default_factory=lambda: dict[int, str]())

type CrowdMapping = Mapping[str, CrowdSchema]

def annotate(ds: CrowdData | str, schema: Iterable[CrowdSchema] = (), allow_unknown: bool = False) -> CrowdData:
    ds = load(ds)

    for item in schema:
        name = item.sheet
        if name in ds:
            df = ds[name]
            for idx, new_col in item.columns.items():
                if idx > len(df.columns) - 1:
                    if allow_unknown:
                        print(f"Index {idx} is out of bounds for dataset {name}, skipping.")
                        continue
                    else:
                        raise ValueError(f"Index {idx} is out of bounds for dataset {name} with {len(df.columns)} columns.")
                
                col = df.columns[idx]
                df.rename(columns={col: new_col}, inplace=True)
                print(f"Renamed column {col} to {new_col} in dataset {name}.")                

            indices = np.arange(len(df)).astype(str) 
            if len(item.index) > 0:
                for idx, new_row in item.index.items():
                    if idx > len(df.index) - 1:
                        if allow_unknown:
                            print(f"Index {idx} is out of bounds for dataset {name}, skipping.")
                            continue
                        else:
                            raise ValueError(f"Index {idx} is out of bounds for dataset {name} with {len(df.index)} rows.")                                
                    print(f"Renamed index {df.index[idx]} to {new_row} in dataset {name}.")            
                df.index = indices
                df.rename(index={df.index[idx]: new_row for idx, new_row in item.index.items()}, inplace=True)
            
    return ds
