import os
import json
from typing import cast
from omegaconf import OmegaConf, DictConfig
import sys
sys.path.append("..")

from base_proxy import BasePerturbationProxy
from typing import List, Tuple

CONF_PATH = "configs/dwk.yaml"

class DeepWukongClassifier:

    def __init__(
        self,
        testcase: str
    ):
        self.testcase = testcase

    def prep_DeepWukong(self, code_str: str):
        config = cast(DictConfig, OmegaConf.load(CONF_PATH))
        self.CWE_PATH = os.path.join(config.data_folder, config.dataset.cve_id)
        self.MODEL_DATA_FOLDER = config.model_data_folder
        self.MODEL_DATASET_NAME = config.model_dataset_name
        self.MODEL_CVE_DATA_FOLDER = os.path.join(self.MODEL_DATA_FOLDER, self.MODEL_DATASET_NAME)
        CSV_PATH = os.path.join(self.MODEL_CVE_DATA_FOLDER, "csv")
        XFG_PATH = os.path.join(self.MODEL_CVE_DATA_FOLDER, "XFG")
        SOURCE_CODE_PATH = os.path.join(self.MODEL_CVE_DATA_FOLDER, "source-code")

        folders = [CSV_PATH, XFG_PATH]

        for foldername in folders:
            if os.path.isdir(foldername):
                command = f"rm -rf {foldername}"
                os.system(command)
        
        filename = os.path.join(SOURCE_CODE_PATH, self.testcase)
        if not os.path.isfile(filename):
            os.system(f"touch {filename}")

        with open(filename, "w") as f:
            f.write(code_str)
    
    def predict(self, code_str: str) -> Tuple[int, float]:
        self.prep_DeepWukong(code_str)

        model_folder_path = self.MODEL_DATA_FOLDER.replace("data", "")[:-1]
        cwd = os.getcwd()
        os.chdir(model_folder_path)
        
        os.system(f"PYTHONPATH=\".\" python src/joern/joern-parse.py")
        os.system(f"PYTHONPATH=\".\" python src/data_generator.py")
        os.system(f"PYTHONPATH=\".\" python src/preprocess/dataset_generator.py")
        os.system(f"PYTHONPATH=\".\" python src/evaluate.py --vul-files {self.testcase} {self.testcase} --dataset-name {self.MODEL_DATASET_NAME} DeepWukong")
        
        src_selected_results_path = os.path.join(model_folder_path, "select_results.json")
        dst_selected_results_path = os.path.join(self.CWE_PATH, "select_results.json")

        os.chdir(cwd)

        os.system(f"cp {src_selected_results_path} {dst_selected_results_path}")

        results = {}

        with open(dst_selected_results_path, "r") as f:
            results = json.load(f)
        
        pred_cnt = len(results[self.testcase])
        vul_cnt = 0
        for slice, pred in results[self.testcase]:
            if pred == 1:
                vul_cnt += 1
        
        output = vul_cnt > 0
        
        # os.system(f"pushd {model_folder_path}")
        # os.system(f"cat env.sh")

        if pred_cnt < 1:
            return (0, 0)

        return (output, vul_cnt / pred_cnt)

class DeepWukongPerturbationProxy(BasePerturbationProxy):
    
    def set_testcase(self, testcase):
        self.testcase = testcase

    def classify(self, document) -> Tuple[bool, float]:
        code_classifier = DeepWukongClassifier(
            testcase=self.testcase
        )
        return code_classifier.predict(document)