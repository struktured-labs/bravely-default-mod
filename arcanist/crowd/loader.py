import pandas as pd, numpy as np
from typing import Mapping, Literal
from functools import lru_cache
import re

@lru_cache
def load_all(file:str, sheet_name=None):
     return pd.read_excel(file, sheet_name=sheet_name)

def _maybe_load_all(file_or_df:str|pd.DataFrame):
    match file_or_df:
        case str() as file:
            return load_all(file)
        case pd.DataFrame() as df:
            return df
        case _:
            raise ValueError(f"Unexpected input: {file_or_df}")


def load(file:str|pd.DataFrame, text, style:Literal['insensitive', 'regex']='insensitive'):

    match style:
        case 'regex':
            pat = re.compile(text)
            def predicate(txt:str) -> bool:
                return len(pat.matches(txt)) > 0
        case 'insensitive':
            def predicate(txt:str) -> bool:
                 return text.lower() in txt.lower()
        
    ds = load_all(file)
    datasets = {}
    for key in ds.keys():
             dss = ds[key]
             if predicate(key):
                 datasets[key]=dss
                 continue
             for col in dss.keys():
                 print(f"check col {key}/{col}")
                 if predicate(col) or (dss[col].dtype.kind in ['S', 'U'] and np.any(dss[col].str.contains(text))):
                     datasets.add(key, dss)
                     break

    return datasets

def col_rename(ds:str|pd.DataFrame, mappings: Mapping[str,str]={}):
    match ds:
        case str():
            ds = load_all(ds)
        case _:
            pass
    for key, col in mappings:



     


     
     
     

     
     
     
     