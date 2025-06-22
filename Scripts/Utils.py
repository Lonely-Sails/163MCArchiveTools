import os
import re
import shutil
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from .Core import check_file_is_encrypt

logger = logging.getLogger('Utils')


def hex_to_bytes(hex_str: str) -> Optional[bytes]:
    try:
        hex_str = hex_str.replace('0x', '')
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except Exception as error:
        logger.error(f'转换16进制失败: {error}！')
        return

def integrity_test(target_path: Path) -> bool:
    try:
        files = os.listdir(target_path)
        if 'level.dat' not in files:
            logger.warning('缺少文件: level.dat')
            return False

        db_path = target_path / 'db'
        if 'db' not in files or not db_path.is_dir():
            logger.warning('缺少文件夹: db/')
            return False

        db_files = os.listdir(db_path)
        manifest_found = False
        current_found = False
        
        for file in db_files:
            if re.match(r'^MANIFEST-[0-9]{6}$', file):
                manifest_found = True
            if file == 'CURRENT':
                current_found = True
            if manifest_found and current_found:
                return True

        if not manifest_found:
            logger.warning('缺少文件: db/MANIFEST-*')
        if not current_found:
            logger.warning('缺少文件: db/CURRENT')
        return False

    except Exception as error:
        logger.warning(f'完整性检查失败: {error}')
        return False


def preprocess_archive(path: Path, mode: int) -> Dict[str, Any]:
    '''预处理目录'''
    try:
        db_path = path / 'db'
        encrypted = []
        decrypted = []
        latest_manifest = None
        cur_file_content = None
        latest_num = -1

        logger.info('正在扫描文件……')

        # 第一遍扫描：找到最新的MANIFEST文件
        for file in os.listdir(db_path):
            if match := re.match(r'^MANIFEST-([0-9]{6})$', file):
                num = int(match.group(1))
                if num > latest_num:
                    latest_num = num
                    latest_manifest = file

        if not latest_manifest:
            raise Exception('预处理失败：找不到必要的 MANIFEST 文件！')

        # 第二遍扫描：处理文件
        for file in os.listdir(db_path):
            if not (
                re.match(r'^MANIFEST-[0-9]{6}$', file)
                or file == 'CURRENT'
                or re.match(r'^[0-9]{6}.ldb$', file)
            ):
                continue

            file_path = db_path / file
            if file_path.is_file():
                with open(file_path, 'rb') as f:
                    temp_buf = f.read()

                if check_file_is_encrypt(temp_buf):
                    encrypted.append(file)
                else:
                    decrypted.append(file)

                if file == 'CURRENT':
                    cur_file_content = temp_buf

        if cur_file_content is None:
            raise Exception('预处理失败：找不到必要的 CURRENT 文件！')

        # 使用MANIFEST文件名加换行符作为before
        manifest_content = latest_manifest + '\n'

        return {
            'encrypted': encrypted,
            'decrypted': decrypted,
            'src_path': db_path,
            'before': manifest_content.encode('ascii'),  # 转换为bytes
            'after': cur_file_content,
        }
    
    except Exception as error:
        logger.warning(str(error))
        raise error


def clone_folder(source: Path, target: Path) -> None:
    logger.info('正在复制文件……')

    if not source.exists():
        return

    if not target.exists():
        target.mkdir(parents=True, exist_ok=True)

    file_list = []

    def prepare_list(source_path: Path, destination_path: Path, files: List[str]):
        for item in os.listdir(source_path):
            source_item = source_path / item
            target_item = destination_path / item
            if source_item.is_file():
                files.append(str(source_item))
            elif source_item.is_dir():
                target_item.mkdir(parents=True, exist_ok=True)
                prepare_list(source_item, target_item, files)

    prepare_list(source, target, file_list)

    for _, file_path in enumerate(file_list, 1):
        source_file = Path(file_path)
        destination_file = target / source_file.relative_to(source)
        shutil.copy2(source_file, destination_file)


def validate_file_integrity(target_path: Path) -> bool:
    try:
        db_path = target_path / 'db'
        if not db_path.is_dir():
            return False
            
        for filename in os.listdir(db_path):
            if not filename.endswith('.ldb'):
                continue
                
            file_path = db_path / filename
            content = file_path.read_bytes()
            if len(content) < 8:
                return False
            magic = int.from_bytes(content[-8:], 'big')
            if magic != 0x57FB808B247547DB:
                return False
        return True
        
    except Exception as error:
        logger.error(f'有效性检测失败: {error}')
        return False