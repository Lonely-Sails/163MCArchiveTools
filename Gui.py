import webview
from webview import Window

import os
import logging
from time import time
from pathlib import Path
from typing import List, Any

from Const import MAX_WORKER_NUMBER, DEFAULT_KEY
from Scripts.Worker import Worker
from Scripts.Utils import hex_to_bytes, integrity_test

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s/%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)

window: Window
logger = logging.getLogger('GUI')


class JavascriptApi:
    workers: List[Worker] = []
    worker_input = Worker.input_queue
    worker_output = Worker.output_queue

    def __init__(self) -> None:
        for index in range(MAX_WORKER_NUMBER):
            worker = Worker(index + 1)
            worker.start()
            self.workers.append(worker)
        logger.info('界面接口初始化完毕！')

    def _process_key(self, custom_key: str) -> bytes:
        '''处理自定义密钥'''
        if custom_key.startswith('0x'):
            key = hex_to_bytes(custom_key)
            if not key:
                raise ValueError('无效的 16 进制密钥！')
        
        key = custom_key.encode('ascii')
        if not key:
            raise ValueError('密钥不能为空！')
        
        # 统一处理密钥长度为8字节
        if len(key) > 8:
            return key[-8:]
        elif len(key) < 8:
            temp = bytearray(8)
            temp[8-len(key):] = key
            return bytes(temp)
        return key
    
    def _get_world_name(self, path: Path) -> str:
        '''读取存档信息'''
        try:
            levelname_path = path / 'levelname.txt'
            if levelname_path.exists():
                return levelname_path.read_text(encoding='Utf-8').strip()
        except Exception as error:
            logger.warning(f'读取存档名称失败: {error}')
        return path.name
    
    def open_path(self, path: str):
        if not os.path.exists(path):
            return {'success': False, 'error': '文件夹不存在！'}
        os.system(f'explorer "{path}"')
        return {'success': True}

    def choose_folders(self):
        result = window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=True)
        if not result:
            return {'success': False, 'error': '未选择文件夹！'}
            
        selected_paths = [str(Path(path)) for path in result]
        logger.info(f'选择了 {len(selected_paths)} 个文件夹。')
        return {'success': True, 'paths': selected_paths}

    def check_paths(self, paths):
        try:
            results = []
            for path in paths:
                path = Path(path)
                valid = path.is_dir() and integrity_test(path)
                world_name = self._get_world_name(path)
                results.append({'path': str(path), 'valid': valid, 'name': world_name})
                logger.info(f'检查路径 {path}: {'有效' if valid else '无效'}')
            return {'success': True, 'data': results}
        except Exception as error:
            logger.error(f'检查路径时出错: {error}')
            return {'success': False, 'error': str(error)}

    def process_batch_decrypt(self, paths, use_custom=False, custom_key=None):
        total_count = len(paths)
        results: List[Any] = [None for _ in range(total_count)]
        logger.info(f'开始批量解密 {total_count} 个文件夹……')
        start_time = time()

        for index, arhive_path in enumerate(paths):
            arhive_path = Path(arhive_path)
            logger.info(f'[{index}/{total_count}] 正在安排任务: {arhive_path}')
            target_path = arhive_path.parent / 'Arhives' / (arhive_path.name + '_Decryption')

            if use_custom:
                if custom_key: args = (arhive_path, target_path, self._process_key(custom_key))
                else: args = (arhive_path, target_path, DEFAULT_KEY)
            else: args = (arhive_path, target_path)

            self.worker_input.put_nowait((index, 'decrypt', args))
        
        for index in range(total_count):
            result_index, result = self.worker_output.get()
            window.evaluate_js(f'showStatus("正在批量解密中（{index + 1}/{total_count}）……", "info")')
            results[result_index] = result

        success_count = sum(1 for result in results if result['success'])
        logger.info(f'批量解密完成: {success_count}/{total_count} 成功，总耗时 {time() - start_time} 秒。')
        return {
            'success': True,
            'results': results,
            'stats': {
                'success': success_count,
                'total': total_count
            }
        }

    def process_batch_encrypt(self, paths):
        total_count = len(paths)
        results: List[Any] = [None for _ in range(total_count)]
        logger.info(f'开始批量加密 {total_count} 个文件夹……')
        start_time = time()

        for index, arhive_path in enumerate(paths):
            arhive_path = Path(arhive_path)
            target_path = arhive_path.parent / 'Arhives' / (arhive_path.name + '_Encrytion')
            args = (arhive_path, target_path)
            self.worker_input.put_nowait((index, 'encrypt', args))
            
        for index in range(total_count):
            result_index, result = self.worker_output.get()
            window.evaluate_js(f'showStatus("正在批量加密中（{index + 1}/{total_count}）……", "info")')
            results[result_index] = result

        success_count = sum(result['success'] for result in results)
        logger.info(f'批量加密完成: {success_count}/{total_count} 成功，总耗时 {time() - start_time} 秒。')
        return {
            'success': True,
            'results': results,
            'stats': {
                'success': success_count,
                'total': total_count
            }
        }


if __name__ == '__main__':
    api = JavascriptApi()
    window_file_path = Path('Window.html')
    window_code = window_file_path.read_text('Utf-8')
    window = webview.create_window('我的世界网易存档加解密工具', html=window_code, js_api=api)
    webview.start(debug=True)

