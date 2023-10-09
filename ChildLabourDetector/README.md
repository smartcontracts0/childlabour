# Child Labor Detector

intro

## Installation

### Environment Setup
1. Install [Python](https://www.python.org/downloads/). This repo running on python **3.9.18**. It's better to install and use Anaconda to manage your environment.
2. Install PIP, make sure it's the latest pip (only using python3) **(if you are not going the anaconda route)**
   ```
   python3 --version
   curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
   python3 get-pip.py
   python3 -m pip install --upgrade pip
   ```
3. Set up a jupyter kernel to run the .ipynb notebooks.
   ```
   pip install jupyter
   python -m ipykernel install --user --name [kernel name]
   ```
4. Install CUDA Toolkit: [Version 11.7](https://developer.nvidia.com/cuda-11-7-0-download-archive). This is for GPU accelaration. If you do not have a nvidia GPU you can skip this and run the project with your CPU.
5. Install pytorch from their [site](https://pytorch.org/) and select the os and cude version you're running on. This was my installation command:

   `conda install pytorch torchvision torchaudio pytorch-cuda=11.7 -c pytorch -c nvidia`

   If you are not running CUDA:

   `pip3 install torch torchvision torchaudio`
6. Clone this repo, pip Install the requirements file
   
   `pip install -r requirements`
