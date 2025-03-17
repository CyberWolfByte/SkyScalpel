# Base Image: PowerShell 7.2 (Includes .NET 6)
FROM mcr.microsoft.com/powershell:7.2.1-ubuntu-20.04
LABEL org.opencontainers.image.authors="Gerry Merino" \
      org.opencontainers.image.description="Container image for https://github.com/Permiso-io-tools/SkyScalpel"

# Install Git and cleanup
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for SkyScalpel (no login shell)
RUN useradd -m -d /home/skyscalpel -s /usr/sbin/nologin skyscalpel && \
    mkdir -p /home/skyscalpel/.local/share/powershell/Modules/SkyScalpel && \
    mkdir -p /home/skyscalpel/.config/powershell && \
    touch /home/skyscalpel/.config/powershell/Microsoft.PowerShell_profile.ps1 && \
    chown -R skyscalpel:skyscalpel /home/skyscalpel

# Clone SkyScalpel Git repo and move all required files
RUN git clone --depth=1 https://github.com/Permiso-io-tools/SkyScalpel.git /tmp/SkyScalpelRepo && \
    mv /tmp/SkyScalpelRepo/* /home/skyscalpel/.local/share/powershell/Modules/SkyScalpel/ && \
    rm -rf /tmp/SkyScalpelRepo && \
    chmod -R +r /home/skyscalpel/.local/share/powershell/

# Automatically import SkyScalpel and run it on PowerShell startup
RUN echo "Import-Module SkyScalpel" >> /home/skyscalpel/.config/powershell/Microsoft.PowerShell_profile.ps1 && \
    echo "Invoke-SkyScalpel" >> /home/skyscalpel/.config/powershell/Microsoft.PowerShell_profile.ps1 && \
    chown -R skyscalpel:skyscalpel /home/skyscalpel/.config/powershell/

# Switch to non-root user
USER skyscalpel

# Start PowerShell and load the profile
CMD ["pwsh", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Login"]
