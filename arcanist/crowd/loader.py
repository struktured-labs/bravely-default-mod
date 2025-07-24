import pandas as pd
import numpy as np
from typing import Mapping
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from dataclasses import dataclass
from dataclasses import field

# Design idea:
# Most functions return a dataframe.
# User can load a file to make a dateframe
# User can edit the dataframe, and save it back to a file.
# Perhaps high level functions can be used to load a file, edit it, and save it back
# Consider a data file to reprsent edits (e.g. a file with columns like "file", "row", "col", "value")

type CrowdData = dict[str, dict[str, pd.DataFrame]]


CROWD_FILE_NAME = "crowd.xls"


def _truncated_path(path: str | Path) -> str:
    path = Path(path)
    # Get last two folders of the path
    # Get last two folders of the path, NOT THE FILENAME itself
    parts = path.parts[-2:]  # Get the last two parts of the path
    return "/".join(parts)  # Join them with a slash


@lru_cache
def _load_all(file: str) -> CrowdData:
    match pd.read_excel(file, sheet_name=None):  # type: ignore
        case dict() as sheets:
            return {_truncated_path(file): sheets}
        case _:
            raise ValueError(
                f"File {file} does not contain any sheets or is not a valid vrecrowd excel file."
            )


def _maybe_load_all(file_or_df: str | Path | CrowdData) -> CrowdData:

    def _load(file: Path) -> CrowdData:
        if file.is_dir():
            # Recursively load all crowd files in the directory
            crowd_files = list(file.glob(f"**/{CROWD_FILE_NAME}"))
            if not crowd_files:
                raise ValueError(f"No crowd.xls file found in directory {file}.")
            result: CrowdData = {}
            for crowd_file in crowd_files:
                result.update(_load_all(crowd_file))
            return result
        else:
            if not file.is_file():
                raise ValueError(f"File {file} does not exist or is not a valid file.")
            return _load_all(file)

    match file_or_df:
        case str() as file:
            file = Path(file)
            return _load(file)
        case Path() as file:
            return _load(file)
        case dict() as crowd_data:
            return crowd_data
        case _:
            raise ValueError(f"Unexpected input: {file_or_df}")


def load(file_or_dir: str | Path, pat: str | None = None) -> CrowdData:
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

    ds = _maybe_load_all(file_or_dir)
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


@dataclass(frozen=True)
class CrowdSchema:
    sheet: str
    index: Mapping[int, str] = field(default_factory=lambda: dict[int, str]())
    columns: Mapping[int, str] = field(default_factory=lambda: dict[int, str]())


type CrowdMapping = Mapping[str, CrowdSchema]


@dataclass(frozen=True)
class CrowdSchemaOverrides:
    path: str
    schemas: CrowdMapping = field(default_factory=lambda: dict[str, CrowdSchema]())

    def __iter__(self):
        """Return an iterator over the schemas."""
        return iter(self.schemas.items())


def annotate(
    crowd_data: CrowdData | Path | str,
    *,
    overrides: Iterable[CrowdSchemaOverrides] = (),
    allow_unknown: bool = False,
) -> CrowdData:

    match crowd_data:
        case dict():
            pass
        case str() | Path() as file:
            crowd_data = load(file)

    for override in overrides:
        raw_path = override.path
        path = _truncated_path(raw_path)
        if path not in crowd_data:
            if allow_unknown:
                print(f"Dataset {path} not found ({raw_path}), skipping annotation.")
                continue
            else:
                raise ValueError(f"Dataset {path} not found in the loaded data.")
        ds: dict[str, pd.DataFrame] = crowd_data[path]
        for sheet, schema in override.schemas.items():
            if sheet in ds:
                df = ds[sheet]
                for idx, new_col in schema.columns.items():
                    if idx > len(df.columns) - 1:
                        if allow_unknown:
                            print(
                                f"Index {idx} is out of bounds for sheet {sheet}, skipping."
                            )
                            continue
                        else:
                            raise ValueError(
                                f"Index {idx} is out of bounds for sheet {sheet} with {len(df.columns)} columns."
                            )

                    col = df.columns[idx]
                    df.rename(columns={col: new_col}, inplace=True)
                    print(f"Renamed column {col} to {new_col} in sheet {sheet}.")

                indices = np.arange(len(df)).astype(str)
                if len(schema.index) > 0:
                    for idx, new_row in schema.index.items():
                        if idx > len(df.index) - 1:
                            if allow_unknown:
                                print(
                                    f"Index {idx} is out of bounds for sheet {sheet}, skipping."
                                )
                                continue
                            else:
                                raise ValueError(
                                    f"Index {idx} is out of bounds for dataset {sheet} with {len(df.index)} rows."
                                )
                        print(
                            f"Renamed index {df.index[idx]} to {new_row} in dataset {sheet}."
                        )
                    df.index = indices  # type: ignore
                    df.rename(
                        index={
                            df.index[idx]: new_row
                            for idx, new_row in schema.index.items()
                        },
                        inplace=True,
                    )

    return crowd_data
