# Password Manager
Simple password manager with simple encryption

Password Manager adalah sebuah aplikasi penyimpan password. Dalam cara kerjanya, aplikasi ini menggunakan algoritma DES dengan sebuah key untuk enkripsi password yang ada. Key yang digunakan oleh algoritma DES berasal dari HASH password admin menggunakan algoritma SHA1.

## About
>This project is created for education purpose at Universitas Indonesia.  
Program ini dibuat oleh:  
-Ridho Maulana - 1706985363  
-Muhamad Istikhori - 1706036923

## Installation
Program dapat dicompile menggunakan GCC dengan menaruh semua file di dalam sebuah folder.  
Atau tersedia project file yang dapat dibuka dengan program "Dev C++" untuk windows yang berada dalam folder compiled, serta terdapat hasil compilenya untuk windows berupa "Pass_Manager.exe".

## Usage
Pastikan file "data_pass_1.txt", "data_pass_2.txt", "data_pass_3.txt" berada dalam folder hasil compile program.  
Jika anda ingin membuat password admin baru hilangkan file "pass_admin.txt". Password default adalah "password".

Saat program pertama dijalankan dan file "pass_admin.txt" tidak ada, maka anda akan diminta membuat password admin baru.  
Setelah membuat password admin baru, anda akan diminta login menggunakan password admin yang baru anda buat, atau password default admin adalah "password" (jika tidak membuat password baru).  
Setelah itu password tersimpan akan ditampilkan dan anda dapat mengubah password tersimpan tersebut.

Password manager ini hanya dapat menyimpan maksimal 3 password, dengan tiap password menggunakan maksimal 10 karakter pengenal, dan 16 karakter password.

## Code Explanation
Dibawah ini merupakan penjelasan utama dari setiap fungsi yang berada dalam file "main.c". Untuk penjelasan secara mendetail mengenai kerja setiap fungsi, dapat ditemukan didalam file "main.c" berupa comment pada setiap perintah yang dilakukan.

`void dapatkanInputKarakter(char *output, int jumlah)`  
fungsi ini bertujuan untuk mendapatkan input dari user berupa karakter dengan jumlah maksimum yang dapat ditentukan, dan menghasilkan output array char.

`void dapatkanInputKarakterUns(BYTE *output, int jumlah, int mask, int padding)`   
fungsi ini bertujuan mirip seperti fungsi dapatkanInputKarakter, namun dengan tambahan pilihan untuk mengganti tampilan pada konsol menjadi tanda "\*" (masking) dan menambahkan karakter spasi untuk mengisi array hingga penuh (padding).

`int dapatkanInputAngka()`  
fungsi ini bertujuan mendapatkan input dari user berupa angka, dan menghasilkan output integer, dengan error checking berupa pemastian input harus berupa angka, bila bukan angka fungsi akan me-return -1.

`int cekLoginPertama()`  
fungsi ini bertujuan untuk memeriksa apakah password utama sudah dibuat atau belum dengan mencari file "pass_admin.txt" yang tersimpan.

`void createPassAdmin(BYTE *buff)`  
fungsi ini bertujuan untuk membuat password utama dari aplikasi pada saat pertama kali aplikasi digunakan. Dan mengubah password tersebut menjadi HASH (20 Byte) melalui algoritma SHA1

`void convertToKey(BYTE *input, BYTE *output)`  
fungsi ini bertujuan mengubah HASH password utama 20 byte menjadi key 7 byte mengunakan bitwise XOR yang akan digunakan pada algorimta DES.

`void createPassAdminFile(BYTE *buff)`  
Hasil Key akan dicari HASHnya kemudian disimpan pada berkas dari password utama yang mana digunakan untuk memverifikasi ketika login aplikasi nanti.

`void masukAdmin(BYTE *buff)`  
fungsi ini bertujuan untuk menampilkan halaman login dan meminta input dari user.

`int cekPassword(BYTE *input)`  
fungsi ini mengecheck hash dari key yang berasal dari password inputan dengan hash dari key yang sudah tersimpan dalam berkas password utama. Apabila hasilnya tidak cocok ,maka aplikasi tidak akan terbuka dan berhenti. Apabila hasilnya cocok, maka akan lanjut ke fungsi menu.

`int menuPassword(BYTE *key)`  
Ini merupakan fungsi dari menu utama yang menampilkan akun dan password yang tersimpan dari berkas penyimpan akun dan password tersebut. Pada menu terdapat 3 sheet yang dapat digunakan untuk menyimpan password berserta nama dari akunnya.Selain 3 sheet data yang bisa diisi terdapat opsi pilihan keluar aplikasi pada menu utama ini. User dapat beraktivitas dengan memilih menu yang tersedia berupa 3 sheet data dan 1 opsi keluar aplikasi yang penomorannya berurutan. User dapat memilih opsi 1 untuk mengubah data sheet 1 dan seterusnya dan nomor 4 untuk keluar aplikasi. Disini terdapat error handling yang mana user tidak mungkin dapat memasukan input selain opsi yang di menu.

`void dapatkanPass(char *nama, BYTE *pass, int nomor)`  
Mendapatkan password yang masih dienkripsi dari file "data_pass_1.txt", "data_pass_2.txt", atau "data_pass_3.txt".

`void decryptPassword(BYTE *pass, BYTE *key)`  
Fungsi ini bertujuan mendekripsi password yang sudah seblumnya diambil dari berkas menggunakan algorima DES dan key yang sudah didapatkan sebelumnya.

`void ambilDaftarPass(char *nama, BYTE *pass)`  
Ketika user memilih untuk mengisi/mengubah data password tersimpan, maka user akan masuk ke fungsi ini yang bertujuan meminta nama login/akun dan passwordnya kepada user.

`Void encryptPassword(BYTE *pass, BYTE *key)`  
Fungsi ini bertujuan mengenkripsi password dari akun yang disimpan oleh user menggunakan Algoritma DES dan key yang sudah didapatkan sebelumnya.

`void createDaftarPassFile(char *nama, BYTE *pass, int nomor)`  
Fungsi Ini bertujuan membuka file lama kemudian mengganti data yang tersimpan dengan data baru yang user masukan sebelumnya berupa nama akun dan hasil enkripsi password.

## Credits
Thanks to Brad Conte for his crypto-algorithms.  
https://github.com/B-Con/crypto-algorithms

## License
This code is released into the public domain free of any restrictions. The author requests acknowledgement if the code is used, but does not require it. This code is provided free of any liability and without any quality claims by the author.
