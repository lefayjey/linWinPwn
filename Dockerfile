# Use the official Ubuntu image as a base
FROM ubuntu:latest

# Install dependencies
RUN apt update && apt install -y \
    sudo \
    wget \
    unzip \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Clone the linWinPwn repository
RUN git clone https://github.com/lefayjey/linWinPwn /opt/linWinPwn

# Make the install script executable
RUN chmod +x /opt/linWinPwn/install.sh

# Run the install script
RUN /opt/linWinPwn/install.sh

# Create wordlists directory
RUN mkdir /opt/lwp-wordlists

# Download and unzip rockyou wordlist 
RUN wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -O "/opt/lwp-wordlists/rockyou.txt.tar.gz"
RUN gunzip "/opt/lwp-wordlists/rockyou.txt.tar.gz"
RUN tar xf "/opt/lwp-wordlists/rockyou.txt.tar" -C "/opt/lwp-wordlists/"
RUN /bin/rm "/opt/lwp-wordlists/rockyou.txt.tar"

# Download cirt usernames wordlist
RUN wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt" -O "/opt/lwp-wordlists/cirt-default-usernames.txt"

# Make the linWinPwn.sh script executable
RUN chmod +x /opt/linWinPwn/linWinPwn.sh

# Add /root/.local/bin to the PATH environment variable
ENV PATH="/root/.local/bin:${PATH}"

# Set the working directory
WORKDIR /opt/linWinPwn

# Set the default shell to bash
ENTRYPOINT ["/bin/bash"]