import os
import json
from typing import cast
from omegaconf import OmegaConf, DictConfig

CONF_PATH = "configs/dwk.yaml"

def main():
    config = cast(DictConfig, OmegaConf.load(CONF_PATH))
    
    CWE_PATH = os.path.join(config.data_folder, config.dataset.cve_id)
    SRC_PATH = os.path.join(CWE_PATH, config.src_folder)
    REDUCTED_SRC_FOLDER = os.path.join(CWE_PATH, config.reducted_src_folder)

    if not os.path.isdir(CWE_PATH):
        os.mkdir(CWE_PATH)
    if not os.path.isdir(SRC_PATH):
        os.mkdir(SRC_PATH)
    if not os.path.isdir(REDUCTED_SRC_FOLDER):
        os.mkdir(REDUCTED_SRC_FOLDER)
    
    

if __name__ == "__main__":
    main()