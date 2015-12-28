# TEST CASES:
# Known data sets

# TRUECRYPT
python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/1-install.raw TCinstall /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/1-install.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/1-install/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/2-open.raw TCopen /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/2-open.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/2-open/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/3-close.raw TCclose /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/3-close.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/3-close/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall.raw TCuninstall /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall.xml --hives /media/forensic/PHD/known_data_sets/TC-7-32/4-uninstall/

# TRUECRYPT: NEW TEST CASES
python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-1-install.raw TC-1-installnew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-1-install.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-1-install/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-2-open.raw TC-2-opennew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-2-open.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-2-open/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-3-close.raw TC-3-closenew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-3-close.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-3-close/

python3.4 Vestigium.py /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall.raw TC-4-uninstallnew /media/forensic/PHD/application_profiles/apxmls_demonstration/data_final/TrueCrypt-7.1a-6.1.7601-FINAL.apxml --dfxml /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall.xml --hives /media/forensic/PHD/known_data_sets/TC/TC-4-uninstall/
