from .classes import CROWD, TABLE, CROWDFILES, TABLEFILE
import os
import shutil
import sys
import lzma
import pickle
import logging
from .utils import get_filename
from typing import Literal, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class PACK:
    def __init__(self, settings: dict[str, str]):
        dir = os.getcwd()
        dirOut = settings.get("output_dir") or f"{os.getcwd()}/romfs_packed"
        fmt : Literal['xls', 'parquet'] = settings.get("fmt", "xls") # type: ignore

        os.makedirs(dirOut, exist_ok=True)
        if settings["game"] == "BD":
            self.pathOut = os.path.join(dirOut, "00040000000FC500", "romfs")
            logFileName = os.path.join(dirOut, "BD_mod.log")
            dataFile = get_filename("data/bd.xz")
            self.headersOut = os.path.join(dirOut, "headers_BD")
        elif settings["game"] == "BS":
            self.pathOut = os.path.join(dirOut, "000400000017BA00", "romfs")
            logFileName = os.path.join(dirOut, "BS_mod.log")
            dataFile = get_filename("data/bs.xz")
            self.headersOut = os.path.join(dirOut, "headers_BS")
        else:
            sys.exit(f"{settings['game']} is not allowed as the game setting!")

        if os.path.isdir(self.pathOut):
            shutil.rmtree(self.pathOut)
        os.makedirs(self.pathOut)

        if not os.path.isdir(self.headersOut):
            os.makedirs(self.headersOut)

        self.pathIn = settings["rom"]
        dataFile = get_filename(os.path.join(self.pathIn, "do_not_remove.xz"))

        with lzma.open(dataFile, "rb") as file:
            crowdSpecs = pickle.load(file)
            crowdFiles = pickle.load(file)
            sheetNames = pickle.load(file)

        logfile = os.path.join(dirOut, f"error.log")
        if os.path.isfile(logfile):
            try:
                os.remove(logfile)
            except:
                pass

        logger = logging.getLogger()

        print("CHDIR: " + self.pathIn)
        os.chdir(self.pathIn)
        moddedFiles: list[list[str]] = []
        skippedCrowd: list[str] = []
        skippedFiles: list[str] = []
        skippedSheets: list[str] = []
        for root, _, files in os.walk("."):
            root = root[2:]
            spreadsheets = list(filter(lambda f: f".{fmt}" in f, files))
            bytefiles = list(filter(lambda f: f".{fmt}" not in f, files))
            bytefiles = list(filter(lambda f: ".xz" not in f, bytefiles))

            if root in crowdFiles:
                crowd = CROWDFILES(root, crowdFiles, crowdSpecs, sheetNames)
                if not crowd.allFilesExist():
                    skippedCrowd.append(f"{root}/crowd.{fmt}")
                else:
                    crowd.loadData(fmt=fmt)
                    if crowd.isModified:
                        crowd.dump(self.pathOut)
                        moddedFiles.append(crowd.moddedFiles)
                    crowd.dumpHeaders(self.headersOut)

                if f"crowd.{fmt}" in spreadsheets:
                    logger.info(f"Removing crowd.{fmt} from spreadsheets in {root}")
                    spreadsheets.remove(f"crowd.{fmt}")
                if "crowd.fs" in bytefiles:
                    bytefiles.remove("crowd.fs")
                if "index.fs" in bytefiles:
                    bytefiles.remove("index.fs")
                bytefiles = list(filter(lambda x: x not in crowdFiles[root], bytefiles))
            else:
                pass

            for sheet in spreadsheets:
                logger.info(f"Loading spreadsheet {sheet} in {root}")
                fname = os.path.join(root, sheet)
                try:
                    table = TABLEFILE(root, sheet, crowdSpecs, sheetNames)
                    table.loadData(fmt=fmt)
                    if table.isModified:
                        table.dump(self.pathOut)
                        moddedFiles.append([fname])
                        name = table.getFileName()
                        if name in bytefiles:
                            bytefiles.remove(name)
                    table.dumpHeaders(self.headersOut)
                except:
                    skippedFiles.append(fname)

            for fileName in bytefiles:
                fname = os.path.join(root, fileName)
                try:
                    table = TABLEFILE(root, fileName, crowdSpecs, sheetNames)
                    table.loadData()
                    if table.isModified:
                        table.dump(self.pathOut)
                        moddedFiles.append([fname])
                except:
                    skippedFiles.append(fname)

        moddedFiles.sort(key=lambda x: x[0])
        skippedCrowd.sort()
        skippedSheets.sort()
        skippedFiles.sort()
        with open(logFileName, "w") as file:
            if moddedFiles:
                for m in moddedFiles:
                    file.write(m.pop(0) + "\n")
                    for mi in m:
                        file.write("    - " + mi + "\n")
            else:
                file.write("No modified files!\n")
                shutil.rmtree(self.pathOut[:-6])  # titleID directory

            if skippedCrowd:
                file.write("\n\n")
                file.write("Skipped crowd files\n")
                for fileName in skippedCrowd:
                    file.write(f"    {fileName}\n")

            if skippedSheets:
                file.write("\n\n")
                file.write("Skipped spreadsheets\n")
                for fileName in skippedSheets:
                    file.write(f"    {fileName}\n")

            if skippedFiles:
                file.write("\n\n")
                file.write("Skipped files\n")
                for fileName in skippedFiles:
                    file.write(f"    {fileName}\n")

        os.chdir(dir)

        logger.removeHandler(logger.handlers[0])
        if os.path.exists(logfile) and not os.path.getsize(logfile):
            os.remove(logfile)


class UNPACK:
    def __init__(self, settings: dict[str, str]):
        dir = os.getcwd()

        if settings["game"] == "BD":
            self.headersPath = os.path.join(dir, "romfs_packed", "headers_BD")
        else:
            self.headersPath = os.path.join(dir, "romfs_packed", "headers_BS")

        self.pathIn = settings["rom"]
        self.pathOut = settings.get("output_dir") or f"{os.getcwd()}/romfs_unpacked"
        self.fmt : Literal['xls', 'parquet'] = settings.get("fmt", "xls")  # type: ignore   

        if os.path.isdir(self.pathOut)  :
            shutil.rmtree(self.pathOut)
        os.makedirs(self.pathOut)

        os.chdir(self.pathIn)
        crowdSpecs: dict[str, Any] = {}
        crowdFiles: dict[str, Any] = {}
        sheetNames: dict[str, Any] = {}
        for root, _, files in os.walk("."):
            root = root[2:]
            for file in files:
                if file == "index.fs":
                    continue
                fileName = os.path.join(root, file)
                if file == "crowd.fs":
                    table = self.loadCrowd(root, fmt=self.fmt)
                    table.dumpFiles(self.pathOut)
                else:
                    table = self.loadTable(fileName, fmt=self.fmt)
                logger.info(f"Loaded {fileName}")

                if table.dumpSpreadsheet:
                    logger.info(f"Dumping spreadsheet {fileName}")
                    try:
                        sheetNames.update(table.dumpSheet())
                    except:
                        logging.exception("Error dumping spreadsheet")
                        sys.exit(f"Error dumping spreadsheet {fileName}")

                crowdSpecs.update(table.crowdSpecs)
                if file == "crowd.fs":
                    baseNames: list[str] = []
                    for key in table.crowdSpecs:
                        name = os.path.basename(key)
                        baseNames.append(name)
                    crowdFiles.update({root: baseNames})

        # Dump data needed for packing
        os.chdir(self.pathOut)
        with lzma.open("do_not_remove.xz", "wb") as file:
            logger.info(f"pickle crowdSpecs to {file}")
            pickle.dump(crowdSpecs, file)
            logger.info(f"pickle crowdFiles to {file}")
            pickle.dump(crowdFiles, file)
            logger.info(f"pickle sheetNames to {file}")
            pickle.dump(sheetNames, file)
            logger.info(f"pickle done for {file}")

        os.chdir(dir)

    def loadCrowd(self, path:str|Path, fmt: Literal['xls', 'parquet'] = "xls"):
        logger.info(f"Loading crowd data from {path} with fmt {fmt}")
        dest = os.path.join(self.pathOut, path)
        if not os.path.isdir(dest):
            os.makedirs(dest)
        src = os.path.join(self.pathIn, path, "crowd.fs")
        shutil.copy(src, dest)
        src = os.path.join(self.pathIn, path, "index.fs")
        shutil.copy(src, dest)
        return CROWD(dest, self.pathOut, self.headersPath, fmt=fmt)

    def loadTable(self, fileName: str, fmt: Literal['xls', 'parquet'] = "xls"):
        logger.info(f"Loading table from {fileName} with fmt {fmt}")
        src = os.path.join(self.pathIn, fileName)
        dest = os.path.join(self.pathOut, fileName)
        base = os.path.dirname(dest)
        if not os.path.isdir(base):
            os.makedirs(base)
        shutil.copy(src, dest)
        return TABLE(dest, self.pathOut, self.headersPath, fmt=fmt)
