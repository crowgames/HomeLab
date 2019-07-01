rm -rf dist;
python3 setup.py sdist;
twine upload dist/*;
#sudo pip3 uninstall HomeLab;
sleep 10;
#sudo pip3 install HomeLab --no-cache-dir;
sudo pip3 install HomeLab -U
