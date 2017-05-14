#!/bin/bash
sudo mkdir /app
sudo /usr/sbin/useradd -m -d /app/ctco-fpos -G wheel ctco-fpos
sudo echo "ctco-fpos:dXZDfTLMttp6" | sudo chpasswd
sudo chown ctco-fpos.ctco-fpos /app
sudo sed -i "s/Defaults    requiretty/Defaults   \!requiretty/g" /etc/sudoers
sudo -s -u ctco-fpos
mkdir -p ~/.ssh && chmod 0700 ~/.ssh && ssh-keygen -t rsa -f ~/.ssh/id_rsa -q -N ""
touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzXCeUY9x8IzXaHL05y3CLa5NRT+hFtVeB3cUTpgeEN9tssUwVMO0MoTPlDrwYYQOKYxssgzgDHF6V1/nMlYy0QdHCCMpudfleocGRI997pcYv/KHZBd1XAR5D91kYKgWSfcMV2/4w6NWESLc6w5coxKHIOzKEmVGKP9ChJLJqDWdDxinjy3lS5zKCG82GvckYJ8UsgWYdUt3eWlClm4EL0jITNu6a3JR3jnkdutyJYqE/Fog+IwAi8TxbuuebgSMCLvcsbyp+Svb35XQ6R0ESVdr3oPAY7d6D0aG/+FWegifP5SZtmZLAs1kQCt6XQJXSwCWsSORzpam+XpTVG3h2w== jenkins@fpos-build.kyiv.epam.com" >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxFM8brmnwqIVwFbjPG8lCViorn75114s+YqPBrPH0bAh09FoewkpWcqqOdclt34Ss+TmtikS9NvV0/e0uEhta82ZT8wOBAEL0snDfpxSKAb2s/G+Feq4d7LOYADbqOBlNIY2B1bMs5TsdogZ0feoivp2AWXKIsfrpRtFENHLQoGglgDJwjXlXIJIKEytEj2UQsv91wJZbyOx5B0FIhRi1qij2qNd0qpcgnqYvBEOQqXwF9uU8ZdBWpVfwVlSKx/NXuc1lWX66IHnW6dzZxhsQOP+uVIuLhuC7as69KZG54CFQK6NW4R3zSIl1e23uTWLKAeDU+MWkfJV0AQx0tNkdw== ctco-fpos@fpos-build.kyiv.epam.com" >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBx91YZ7bXieaB7YcBkJ1gVvqY+Son0LHRjmCGMTDe1qZVTmFy6O+So92PCy1Eif51eT95IpWP0z2QNboppPG+d8tDj9nB2MIJXKouTyNdXykDiAAeHi748wdKBD/eFy8pEhJhabAwM/P+Og4OYdi/PJNA8AtGOLV4CsvkZrk4rLPRzvWxMDEeZfiLacIbVhdp2NDsDd89dF9+0C0MTKLeuS1G0DUNM2lIz7f9icH3qo/yOekev3/OqXHJPmHWG4yujvQdYfw5q4WkT408LPvXtoK0rTG/Igllyb957t/+ViStu8e4FcZ8gDah8Urg/76vQoVtRlx/mOosJw4Qbymr gagarin@ubuntu" >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCe/Ky6wVpvj4m8AOWqt1G5pibk//MldSm1YnEzhYr8dDRK5DejZ3ggv+6Sm7IOsJMR1P2MKt1/TvnmuCUH8zXMZi8GjtddPeb2gEWTggtr1aXaPFSYNweRnHlVtyxLYBF5epID23EWv71sfAocYd4TC4FH7uPosVY75ppiq0VNs9a7UeawiiuJ2Bgfnmk1lsInzzHRu3yAiTx8RNGiTD4A5oYIvmV5KxG/YgGg4L3E3R2sqOUGjWRq+D9NvEhpU0cBdtOBPNT1Vgo8TSsEKmcEFO/WCTz+bYq1VezdoNRIhJB5vfPPgoFj1b8/oqiPBmdQ7v/JMyWJDxpEDzii+8R5 mykola_gromivchuk@epam.com" >> ~/.ssh/authorized_keys
