import logging
import shutil
import logging
from time import time
from queue import Queue
from pathlib import Path
from typing import Optional
from threading import Thread

from .Core import encrypt_file, decrypt_file
from .Utils import preprocess_archive, clone_folder, validate_file_integrity


class Worker(Thread):
    input_queue: Queue = Queue()
    output_queue: Queue = Queue()

    def __init__(self, index: int) -> None:
        Thread.__init__(self, daemon=True, name=f'Worker-{index}')
        self.logger = logging.getLogger(f'Worker-{index}')
        self.logger.info('工作线程初始化成功！')

    def run(self):
        while True:
            self.logger.info('正在等待任务……')
            task_index, task_name, task_args = self.input_queue.get()
            self.logger.info(f'接受任务：{task_name} {task_args}')
            start_time = time()
            try:
                if task_name == 'decrypt':
                    self.active_decrypt(*task_args)
                elif task_name == 'encrypt':
                    self.default_encrypt(*task_args)
            except Exception as error:
                self.output_queue.put_nowait((task_index, {'success': False, 'message': str(error)}))
                self.logger.info(f'任务失败，耗时为 {time() - start_time} 秒。')
                continue
            self.output_queue.put_nowait((task_index, {'success': True}))
            self.logger.info(f'任务成功，耗时为 {time() - start_time} 秒。')

    def active_decrypt(self, source: Path , target: Path, custom_key: Optional[bytes] = None) -> None:
        '''使用给定密钥解密'''
        preprocess = preprocess_archive(source, 1)
        encrypted = preprocess['encrypted']
        if not encrypted:
            raise Exception('解密失败：未发现加密文件！')
        clone_folder(source, target)
        self.logger.info(f'发现加密文件: {', '.join(encrypted)}')
        try:
            if not custom_key:
                self.logger.info('尝试获取密钥……')
                # 使用MANIFEST文件名(包含\n)和CURRENT文件内容(去除魔数)
                manifest_name = preprocess['before']  # 已经是bytes类型
                current_content = preprocess['after'][4:]  # CURRENT文件内容(去除魔数)

                # 长度不等(与JS版本保持一致)
                if len(manifest_name) != len(current_content):
                    raise Exception('解密失败：自动获取密钥失败，文件长度不匹配！')

                # 创建8字节密钥
                key = bytearray(8)
                for index in range(min(len(manifest_name), len(current_content))):
                    key[index % 8] = manifest_name[index] ^ current_content[index]

                # 验证第二段8字节是否匹配
                if len(manifest_name) >= 16:
                    second_key = bytearray(8)
                    for index in range(8, 16):
                        second_key[index % 8] = manifest_name[index] ^ current_content[index]
                    
                    if bytes(key) != bytes(second_key):
                        raise Exception('解密失败：自动获取密钥失败，密钥校验不匹配！')
                
                self.logger.info(f'成功获取密钥: 0x{key.hex()}')
            else:
                key = custom_key

            self.logger.info('正在解密……')
            for file in encrypted:
                file_path: Path = target / 'db' / file
                if buffer := decrypt_file(file_path.read_bytes(), key):
                    file_path.write_bytes(buffer)
                else: raise Exception('解密失败，可能是密钥错误。')

            self.logger.info('解密完成，正在验证文件有效性……')
            if validate_file_integrity(target):
                self.logger.info('文件验证通过，解密成功！')
                return
            raise Exception('文件验证失败，解密结果可能不正确！')

        except Exception as error:
            self.logger.error(str(error))
            if target.exists():
                shutil.rmtree(target)
            raise error


    def default_encrypt(self, source: Path, target: Path) -> None:
        '''使用默认密钥加密'''
        preprocess = preprocess_archive(source, 0)
        if preprocess is None:
            return
        if preprocess['encrypted']:
            raise Exception('加密失败：发现已加密文件，请先解密！')

        files_to_encrypt = preprocess['decrypted']
        if not files_to_encrypt:
            raise Exception('加密失败：没有需要加密的文件！')

        try:
            clone_folder(source, target)

            self.logger.info('正在加密……')
            for filename in files_to_encrypt:
                file_path: Path = target / 'db' / filename
                if buffer := encrypt_file(file_path.read_bytes()):
                    file_path.write_bytes(buffer)
                else: raise Exception('加密失败：发生未知加密错误!')

            self.logger.info(f'加密完成！文件保存在: {target}')

        except Exception as error:
            self.logger.error(str(error))
            if target.exists():
                shutil.rmtree(target)
            raise error
        

