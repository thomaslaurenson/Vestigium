# TEST CASES:
# Known data sets

# TRUECRYPT
python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/1-install.raw output/TCinstall /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/1-install.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/1-install/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/2-open.raw output/TCopen /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/2-open.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/2-open/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/3-close.raw output/TCclose /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/3-close.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/3-close/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall.raw output/TCuninstall /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall/

# TRUECRYPT: NEW TEST CASES
python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-1-install.raw output/TC-1-installnew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-1-install.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-1-install/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-2-open.raw output/TC-2-opennew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-2-open.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-2-open/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-3-close.raw output/TC-3-closenew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-3-close.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-3-close/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall.raw output/TC-4-uninstallnew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall/
