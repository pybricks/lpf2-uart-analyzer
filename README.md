# lpf2-uart-analyzer

Python script for decoding .csv files containing UART data captured from a
logic analyzer from LEGO UART I/O devices (EV3 and Powered Up).


## Hacking

Get Python:

Need Python >= 3.6. Highly recommend using `pyenv` to install Python.

Get Poetry:

    # *nix
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
    # Windows PowerShell
    (Invoke-WebRequest -Uri https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py -UseBasicParsing).Content | py -3

    # configure venv in project directory
    poetry config virtualenvs.in-project true

Get VS Code:

https://code.visualstudio.com/

Get the code:

    git clone https://github.com/pybricks/lpf2-uart-analyzer
    cd lpf2-uart-analyzer
    poetry install
    code .
