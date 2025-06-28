from .release import RELEASE
import os
import shutil
import hashlib
import lzma
import pickle
import os
import argparse
import logging
from pathlib import Path
from .core.utils import get_filename
from .core.rom import UNPACK, PACK

MAIN_TITLE = f"Bravely Crowd v{RELEASE}"
from typing import Literal

GameType = Literal['BD', 'BS']

class CliApplication:
    def __init__(self, settings:dict[str,str]|None=None):
        self.homeDir = os.getcwd()
        self.settings :dict[str, str]= settings or dict()
        self.initialize_cli()


    def initialize_cli(self):

        self.warnings = []
        self.settings['release'] = ""
        self.settings['rom'] = ""
        self.settings['game'] = ""
        
        parser = argparse.ArgumentParser(description=MAIN_TITLE, usage="%(prog)s [options] <action>")
        parser.add_argument("action", type=str, choices=['unpack', 'pack'], help="Action to perform. Required.")
        parser.add_argument('-r', '--rom', type=str, help='Path to the romfs directory. Required.', required=True, default=None)
        parser.add_argument('-g', '--game', type=str, choices=['BD', 'BS'], default='BD', help='Game type. Defaults to Bravely Default (BD)')
        parser.add_argument('-o', '--output-dir', type=str, default=None, help="Target output directory. Defaults to romfs_{action}.")


        args = parser.parse_args()
        if args.rom:
            self.settings['rom'] = os.path.realpath(args.rom)
        else:
            raise ValueError('No rom path provided')
        if args.game:
            self.settings['game'] = args.game
        else:
            raise ValueError('No game type provided')
   
        if args.output_dir:
            print(f"Output directory: {args.output_dir}")
            self.settings["output_dir"] = os.path.realpath(args.output_dir)
        else:
            self.settings["output_dir"] = os.getcwd() + "/" + f"romfs_{args.action}ed"
        print(f"Output directory: {self.settings['output_dir']}")
        match args.action:
            case 'unpack':
                self.settings['action'] = 'unpack'
                self.unpack()
            case 'pack':
                self.settings['action'] = 'pack'
                self.pack()
            case _:
                raise ValueError('Invalid action provided')

    def getRomPath(self, path:str|None=None):

        if not path:
            raise ValueError('Path is None')

        path, dir = os.path.split(path)
        while dir:
            # Allow for romfs/<titleID> to be selected
            is_romfs = 'romfs' in dir.lower()
            is_titleid = '00040000' in dir
            if is_romfs:
                _, directories, _ = next(os.walk(os.path.join(path, dir)))
                if any(['0004000' in d for d in directories]):
                    if len(directories) == 1 and '00040000' in directories[0]:
                        dir = '/'.join([dir, directories[0]])
                    if '00040000000FC500' in directories:
                        dir = '/'.join([dir, '00040000000FC500'])
                    elif '000400000017BA00' in directories:
                        dir = '/'.join([dir, '000400000017BA00'])
                    else:
                        raise ValueError('No known titleID found')
                        
            if is_romfs or is_titleid:
            # if 'romfs' in dir or 'RomFS' in dir or '0004000000' in dir:
                # path = os.path.join(path, dir)
                path = '/'.join([path, dir])
                self.settings['rom'] = path
                self.checkForGame()
                return
            path, dir = os.path.split(path)

    def checkForGame(self):
        self.settings['game'] = ""

        # Specified path exists
        path = self.settings['rom']
        if not os.path.isdir(path):
            return

        os.chdir(self.homeDir)

    def initialize_settings(self, settings: None|dict[str,str]=None):
        self.settings['release'] = RELEASE
        if settings is None:
            return
        for key, value in settings.items():
            if key == 'release': continue
            if key not in self.settings: continue
            self.settings[key]=value
        self.getRomPath(path=self.settings['rom'])
        if self.settings['rom'] == '':
            self.settings['game'] = ''

    def _checkSettings(self):
        if self.settings['rom'] == '':
            print("Empty rom path")
            return False
        elif self.settings['game'] == '':
            print("Must identify game")
            return False
        return True

    def _unpackPopup(self):
        print("Unpacking")
        
    def _packPopup(self):
        print("Packing")
        
    def _unpack(self):
        if not self._checkSettings():
            return
        if os.path.isdir('romfs_unpacked'):
            self._unpackPopup()
        else:
            self.unpack()

    def _pack(self):
        if not self._checkSettings():
            return
        if os.path.isdir('romfs_packed'):
            self._packPopup()
        else:
            self.pack()

    def unpack(self, settings: dict[str,str,]|None=None):
        
        dir = os.getcwd()
        unpacked, error = unpack(settings or self.settings)
        if unpacked:
            print('Unpacking...done!')
        else:
            print('Mrgrgrgrgr!')
            print('Unpacking failed:' + str(error))
        os.chdir(dir)

    def pack(self, settings:dict[str,str,]|None=None):

        dir = os.getcwd()
        print('Packing....')
        packed, error = pack(settings or self.settings)
        if packed:
            print('Packing...done!')
        else:
            print('Mrgrgrgrgr!')
            print('Packing failed: ' + str(error))
        os.chdir(dir)


def unpack(settings: dict[str,str]) -> tuple[bool, Exception|None]:
    try:
        UNPACK(settings)
    except (Exception,) as e:
        logging.exception('Unpack error')
        return False, e
    return True, None

def pack(settings: dict[str,str]) -> tuple[bool, Exception|None]:
    try:
        PACK(settings)
    except (Exception,) as e:
        return False, e
    return True, None

def main():
    logging.basicConfig(level=logging.DEBUG)
    CliApplication()

if __name__ == '__main__':
    main()
