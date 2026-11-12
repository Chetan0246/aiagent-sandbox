# -*- mode: ruby -*-
# vi: set ft=ruby :
# Aegis-Sandbox Automated Vagrant Environment
# Spins up the Debian 13 / Debian 12 minimal VM sandbox environment

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "debian-minimal"

  config.vm.network "private_network", ip: "192.168.122.71"

  config.vm.provider "libvirt" do |lv|
    lv.memory = 1024
    lv.cpus = 2
    lv.nested = true
    lv.driver = "kvm"
  end

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = 2
  end

  config.vm.provision "shell", path: "scripts/provision.sh"
end
