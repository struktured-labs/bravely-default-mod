import pandas as pd
import numpy as np
from typing import Mapping, Sequence
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from dataclasses import dataclass
from dataclasses import field
import yaml

type CrowdData = dict[str, dict[str, pd.DataFrame]]

CROWD_FILE_NAME = "crowd.xls"
DEFAULT_ROOT_DIR = "../build/crowd-dev-unpacked"

def _truncated_path(path: str | Path) -> str:

    path = Path(path)
    if len(path.parts) == 2:
        return str(path).strip("/")
    parts = path.parts[-3:-1]
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




@dataclass(frozen=True)
class CrowdSchemaOverrides:
    path: str
    schemas: Sequence[CrowdSchema] = field(default_factory=lambda: list[CrowdSchema]())

    def __iter__(self):
        """Return an iterator over the schemas."""
        return iter(self.schemas)

    class Builder:
        def __init__(self, path: str):
            self.path = path
            self.schemas: list[CrowdSchema] = []
        def add(
            self,
            sheet: str, *,
            index: Mapping[int, str] | None = None,
            columns: Mapping[int, str] | None = None,
        ) -> 'CrowdSchemaOverrides.Builder':
            if index is None:
                index = {}
            if columns is None:
                columns = {}
            self.schemas.append(CrowdSchema(sheet, index, columns))
            return self
        def build(self) -> 'CrowdSchemaOverrides':
            return CrowdSchemaOverrides(self.path, self.schemas)

    @staticmethod
    def builder(path: str) -> 'CrowdSchemaOverrides.Builder':
        return CrowdSchemaOverrides.Builder(path)
   
    @staticmethod
    def save(overrides: Iterable['CrowdSchemaOverrides'], root_dir: str | Path = ".", file_name: str | Path = "crowd_overrides.yaml") -> Path:
        """Save the crowd schema overrides to a file.

        Args:
            overrides (Iterable[CrowdSchemaOverrides]): The overrides to save.
            root_dir (str | Path): The directory where the file will be saved.
        """
        file_path = Path(root_dir) / file_name
        with open(file_path, "w") as f:
            ser = yaml.dump(overrides)
            f.write(ser)
        return file_path

    @staticmethod
    def load(file_or_dir: str | Path = DEFAULT_ROOT_DIR, *, file_name: str | Path = "crowd_overrides.yaml") -> Iterable['CrowdSchemaOverrides']:
        """Load crowd schema overrides from a file.

        Args:
            file_or_dir (str | Path): The file or directory where the overrides are stored.
            file_name (str | Path): The name of the overrides file.
        
        Returns:
            Iterable[CrowdSchemaOverrides]: The loaded overrides.
        """
        file_path = Path(file_or_dir) / file_name
        if not file_path.is_file():
            raise ValueError(f"File {file_path} does not exist.")
        with open(file_path, "r") as f:
            return yaml.safe_load(f)
        
def annotate(
    crowd_data: CrowdData | Path | str,
    *,
    overrides: Iterable[CrowdSchemaOverrides]|CrowdSchemaOverrides = (),
    allow_unknown: bool = False,
) -> CrowdData:

    match crowd_data:
        case dict():
            pass
        case str() | Path() as file:
            crowd_data = load(file)

    match overrides:
        case CrowdSchemaOverrides() as override:
            overrides = [override]
        case Iterable() as overrides:
            pass

    for override in overrides:
        raw_path = override.path
        path = _truncated_path(raw_path)
        if path not in crowd_data:
            if allow_unknown:
                print(f"Dataset {path} not found ({raw_path}), skipping annotation.")
                continue
            else:
                raise ValueError(f"Dataset {path} derived from {raw_path} not found in the loaded data.")
        ds: dict[str, pd.DataFrame] = crowd_data[path]
        for schema in override.schemas:
            sheet = schema.sheet
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


def save(crowd_data: CrowdData, root_dir: str|Path = DEFAULT_ROOT_DIR):
    """Save the crowd data to Excel files.

    Args:
        crowd_data (CrowdData): The crowd data to save.
        root_dir (str | Path): The directory where the files will be saved.
    """
    for path, sheets in crowd_data.items():
        prefix=Path(root_dir) / Path(path) 
        prefix.mkdir(parents=True, exist_ok=True)
        file_path = prefix / CROWD_FILE_NAME
        with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
            for sheet_name, df in sheets.items():
                df.to_excel(writer, sheet_name=sheet_name, index=True) #type: ignore
        print(f"Saved crowd data to {file_path}")
