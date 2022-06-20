import os
import sys
import json
import shutil
from typing import cast
from omegaconf import OmegaConf, DictConfig
sys.path.append("..")

from explainer import SequenceExplainer
from counterfactual_search import GreedySearch
from code_reductions.reducer_proxies import CCodePerturbationProxy

CONF_PATH = "configs/dwk.yaml"

def main():
    config = cast(DictConfig, OmegaConf.load(CONF_PATH))
    CWE_PATH = os.path.join(config.data_folder, config.dataset.cve_id)
    SRC_PATH = os.path.join(CWE_PATH, config.src_folder)
    REDUCTED_SRC_FOLDER = os.path.join(CWE_PATH, config.reducted_src_folder)

    for filename in os.listdir(SRC_PATH):
        src_file_path = os.path.join(SRC_PATH, filename)

        code_str = ""
        with open(src_file_path, "r") as f:
            code_str = f.read()

        proxy = CCodePerturbationProxy()
        explainer = SequenceExplainer(GreedySearch(proxy))
        preturbations = explainer.explain(code_str).perturbation_tracking
        print(len(preturbations))

        reducted_file_path = os.path.join(REDUCTED_SRC_FOLDER, filename)
        
        if os.path.isfile(reducted_file_path):
            os.system(f"rm {reducted_file_path}")
        os.system(f"touch {reducted_file_path}")

        with open(reducted_file_path, "w") as f:
            f.write(code_str)


if __name__ == "__main__":
    main()