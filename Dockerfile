# Use the official Ubuntu image as a base
FROM ubuntu:latest

# Install dependencies
RUN apt update && apt install -y \
    sudo \
    wget \
    unzip \
    zsh \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Clone the linWinPwn repository
RUN git clone https://github.com/lefayjey/linWinPwn /opt/linWinPwn

# Make the install script executable
RUN chmod +x /opt/linWinPwn/install.sh

# Run the install script
RUN /opt/linWinPwn/install.sh

# Make the linWinPwn.sh script executable
RUN chmod +x /opt/linWinPwn/linWinPwn.sh

# Set the default shell to zsh
CMD ["zsh"]
