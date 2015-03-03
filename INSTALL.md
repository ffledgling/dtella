Linux
=====

You need the following things installed. (Will vary by distribution).

- Python (2.7+)
- python-virtualenv
- pip

There are two ways to install and setup dtella on a Linux system, the first using Virtual Environments is cleaner and recommended.

### Virtual Environments

Do the following
```
    cd ~ # Or go to some other suitable folder
    virtualenv dtella && cd $_ && . bin/activate;
    git clone https://github.com/ffledgling/dtella.git src
    pip install -v twisted PyCrypto dnspython gdata
```

This installs the python dependencies required.

### System Level install

The following Python libraries need to be installed at the system level:
- Twisted
- PyCrypto
- gdata
- dnspython

You can do this using `sudo pip install` or your distribution's package manager.

Then do the following:

```
    cd ~ # Or go to some other suitable folder
    git clone https://github.com/ffledgling/dtella.git src
```

This takes care of downloading the source code.

### Running dtella

From within the same terminal (i.e from within the active virtualenv), do the following:

```
    cd src && ./dtella.py
```

This should start the dtella server in that tab.  
Then simply follow the instructions given in the README.md to connect to the
hub.



Mac OSX
=======

This method assumes you have brew installed.

```
    brew install python # This should pull in pip
    sudo pip install virtualenv
    cd ~ # Or go to some other suitable folder
    virtualenv dtella && cd $_ && . bin/activate;
    git clone https://github.com/ffledgling/dtella.git src
    pip install -v twisted PyCrypto dnspython gdata
```

This completes the dependencies required.
From within the same terminal, do the following:

```
    cd src && ./dtella.py
```

This should start the dtella server in that tab.  
Then simply follow the instructions given in the README.md to connect to the
hub.


Windows
=======

Avoid using this Operating System when given the choice.
It'll probably be slow, the network libraries are subpar.



