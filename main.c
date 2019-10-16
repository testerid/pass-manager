/*
   Credits to Brad Conte for his crypto-algorithms. sha1 and des library.
*/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include<stdlib.h>
#include<conio.h>
#include "sha1.h"
#include "des.h"

//global variable
char namafilepassadmin[] = "pass_admin.txt"; //nama file untuk menyimpan password admin
char namafiledaftarpassword[3][16] = {{"data_pass_1.txt"},{"data_pass_2.txt"},{"data_pass_3.txt"}}; //nama file untuk menyimpan daftar password

//Prototyping
void dapatkanInputKarakter(char *output, int jumlah);							//mendapatkan input dari user berupa karakter, menghasilkan output char
void dapatkanInputKarakterUns(BYTE *output, int jumlah, int mask, int padding);	//mendapatkan input dari user berupa karakter, menghasilkan output unsigned char
int dapatkanInputAngka();														//mendapatkan input dari user berupa angka, menghasilkan output integer
int cekLoginPertama();															//mengecek apakah login pertama
void createPassAdmin(BYTE *buff);												//membuat sandi admin baru
void createPassAdminFile(BYTE *buff);											//membuat file penyimpanan hash dari key (yang berasal dari password) untuk memverivikasi login selanjutnya
void masukAdmin(BYTE *buff);													//meminta password admin
void convertToKey(BYTE *input, BYTE *output);									//mengubah sandi menjadi key 7 byte untuk algoritma des
int cekPassword(BYTE *input);													//membandingkan hash dari key(yang berasala dari password) apakah sesuai dengan yang sudah tersimpan
void dapatkanPass(char *nama, BYTE *pass, int nomor);							//mendapatkan password yang masih dienkripsi dari file penyimpanan
void decryptPassword(BYTE *pass, BYTE *key);									//mendekripsi password dari penyimpanan dengan algoritma des dan key yang sesuai
int menuPassword(BYTE *key);													//menampilkan password tersimpan, dan menu utama
void ambilDaftarPass(char *nama, BYTE *pass);									//mengambil data nama dan password baru
void encryptPassword(BYTE *pass, BYTE *key);									//mengenkripsi password baru
void createDaftarPassFile(char *nama, BYTE *pass, int nomor);					//menyimpan password yang sudah dienkripsi ke file

int main()
{
	BYTE inputSandiAdmin[16];						//input password admin
	BYTE hasilKey[7];								//hasil pengolahan sha1 password sebagai key algoritma des
	
	if(cekLoginPertama())
	{
		//Mengecek keberadaan file password admin, bila tidak ada berarti ini login pertama kali
		createPassAdmin(inputSandiAdmin);			//membuat sandi admin baru
		convertToKey(inputSandiAdmin,hasilKey);		//mengubah sandi admin ke key untuk algoritma des
		createPassAdminFile(hasilKey);				//menyimpan hash dari key untuk verivikasi setiap login setelah ini
	}
	
	masukAdmin(inputSandiAdmin);					//login admin
	
	convertToKey(inputSandiAdmin,hasilKey);			//mengubah password menjadi key untuk algoritma des
	
	if(cekPassword(hasilKey))
	{
		//apabila password sesuai maka masuk ke program
		while(1)
		{
			//ulangi peritah dibawah, sampai user ingin keluar
			int menu = menuPassword(hasilKey);		//tampilkan password tersimpan dan menu, serta dapatkan nilai hasil pilihan user
			if(menu < 4)
			{
				//apabila ingin mengubah password tersimpan
				char namaBaru[11]; 									//variable sementara penyimpan nama identitas password
				BYTE passBaru[16];									//variable sementara penyimpan password
				ambilDaftarPass(namaBaru, passBaru);					//meengambil data dari user
				encryptPassword(passBaru, hasilKey);				//mengenkripsi password
				createDaftarPassFile(namaBaru, passBaru, menu-1);	//menyimpan hasil enkripsi kedalam file
			}else
			{
				break;
			}
		}
	}else
	{
		printf("Password yang anda masukan salah\n");
		printf("Selamat tinggal\n");
	}
	

	return(0);
}


//fungsi fungsi modular

void dapatkanInputKarakter(char *output, int jumlah)
{
	int i = 0;
    while(1)
	{
		//loop terus apabila belum ditekan <enter>
		if(i<jumlah)
		{
			//apabila masih dibawah jumlah yang diinginkan, simpan input
			output[i] = getch();
		    if(output[i] == 13)
	        {
	        	//apabila sebelum jumlah karakter penuh, sudah ditekan <enter>
	        	//penambahan karakter <spasi> untuk mengisi kekurangan karakter
				int t;
	            for(t=i;t<jumlah;t++)
	            {
	            	output[t] = ' ';
				}
	            break;
	        } else if(output[i] == 8) 
	        {
	        	//apabila ditekan <backspace>
				if(i == 0)
				{
	        		//jika di index awal, jangan sampai menjadi index negatif
					output[i] = ' ';
	        		i = i-1;
				} else{
					printf("\b \b");	//hapus karakter yang sudah terlanjur diprint
					output[i] = ' ';	//ubah karakter <backspace> yang terlanjur disimpan menjadi <spasi>
					i = i-2;			//mundur 2 index, kenapa 2? bukan 1? karena setelah ini ada penambahan 1 oleh i++, maka untuk mundur satu karakter harus dikurang 2
		        	output[i+1] = ' ';	//ubah karakter yang disimpan sebelum <backspace> menjadi <spasi>
				}
			} else
	        {
	        	//apabila bukan <enter> atau <backspace> tampilkan karakter yang ditulis saat ini
	            printf("%c", output[i]);
	        }
	        i++;	//tambahkan counter index
		} else
		{
			//apabila index sudah melebihi jumlah yang diinginkan, tunggu <enter> atau <backspace>
			char ch = getch();
			if(ch == 13)
			{
				//apabila <enter>, berarti sudah selesai
				break;
			} else if(ch == 8)
			{
				//apabila <backspace>, berarti hapus karakter sebelumnya
				printf("\b \b");
				i = i-1;	//index dikurang 1, untuk mundur 1 index, tidak seperti diatas (dikurang 2), karena disini tidak ada i++
		        output[i] = ' ';
			}
		}
	}
}

void dapatkanInputKarakterUns(BYTE *output, int jumlah, int mask, int padding)
{
	int i = 0;
    while(1)
	{
		//loop terus apabila belum ditekan <enter>
		if(i<jumlah)
		{
			//apabila masih dibawah jumlah yang diinginkan, simpan input
			output[i] = getch();
		    if(output[i] == 13)
	        {
	        	//apabila sebelum jumlah karakter penuh, sudah ditekan <enter>
				if(padding == 1)
	        	{
	        		//apabila diinginkan penambahan karakter <spasi> untuk mengisi kekurangan karakter
	        		int t;
		            for(t=i;t<jumlah;t++)
		            {
		            	output[t] = ' ';
					}	
				} else
				{
					//apabila tidak diinginkan penambahan karakter, dan mengakhiri dengan karakter <null>
					output[i] = '\0';
				}
	            break;
	        } else if(output[i] == 8) 
	        {
	        	//apabila ditekan <backspace>
				if(i == 0)
				{
	        		//jika di index awal, jangan sampai menjadi index negatif
					output[i] = ' ';
	        		i = i-1;
				} else{
					printf("\b \b");	//hapus karakter yang sudah terlanjur diprint
					output[i] = ' ';	//ubah karakter <backspace> yang terlanjur disimpan menjadi <spasi>
					i = i-2;			//mundur 2 index, kenapa 2? bukan 1? karena setelah ini ada penambahan 1 oleh i++, maka untuk mundur satu karakter harus dikurang 2
		        	output[i+1] = ' ';	//ubah karakter yang disimpan sebelum <backspace> menjadi <spasi>
				}
			} else
	        {
	        	//apabila bukan <enter> atau <backspace> tampilkan karakter yang ditulis saat ini
				if(mask == 1)
	        	{
	        		//apabila diinginkan masking, tidak memperbolehkan penampilan karakter (diubah jadi <*>)
					printf("*");
				} else
				{
					printf("%c", output[i]);
				}
	        }
	        i++; //tambahkan counter index
		} else
		{
			//apabila index sudah melebihi jumlah yang diinginkan, tunggu <enter> atau <backspace>
			char ch = getch();
			if(ch == 13)
			{
				//apabila <enter>, berarti sudah selesai
				break;
			} else if(ch == 8)
			{
				//apabila <backspace>, berarti hapus karakter sebelumnya
				printf("\b \b");
				i = i-1; //index dikurang 1, untuk mundur 1 index, tidak seperti diatas (dikurang 2), karena disini tidak ada i++
		        output[i] = ' ';
			}
		}
	}
}

int dapatkanInputAngka()
{
    //digunakan untuk mengecek apakah input berupa angka dan bukan huruf
    int input;
    int cek_error_huruf = scanf("%d", &input); //jika yang dimasukan berupa huruf maka akan bernilai kurang dari 1
    if (cek_error_huruf < 1)
    {
        //karena kesalahan input berupa huruf akan meninggalkan huruf tersebut pada buffer maka perlu dihilangkan dari buffer
        char kosong[50];
        scanf("%[^\n]%*c", kosong);
        //beritahu kesalahan ke pengguna
        system("cls");
    	printf("+++++++++++++++Error+++++++++++++++\n");
        printf("\n\nError : Yang anda masukan bukan angka, silahkan masukan angka saja!\n");
        printf("Tekan tombol apa saja untuk melanjutkan\n");
        getch();
        system("cls");
        return -1; //hasil fungsi -1 menandakan erroe
    }
	
    return input;
}

int cekLoginPertama(){
	FILE *cekAda;
	if ((cekAda = fopen(namafilepassadmin, "rb")) != NULL)
	{
		//apabila file ada dan bisa dibuka, berarti bukan login pertama
		fclose(cekAda);
		return 0;
	}else {
		//apabila file tidak ada, berarti login pertama
		return 1;
	}
}

void createPassAdmin(BYTE *buff)
{
	system("cls");
    printf("+++++++++++++++Pendaftaran+++++++++++++++\n");
    printf("\nAnda terdeteksi belum pernah menjalankan program ini\n");
    printf("\nSilahkan masukan sandi admin baru (maksimal 16 karakter)\n");
    printf("Jika sudah selasai, tekan <enter>\n\n");
    printf("Sandi admin : ");
    
    dapatkanInputKarakterUns(buff,16,0,0); //mendapatkan sandi baru
    
	system("cls");
}

void createPassAdminFile(BYTE *buff)
{
	BYTE temp[SHA1_BLOCK_SIZE];				//penyimpanan sementara hasil hash key
	
	SHA1_CTX ctx;							//inisialisasi struct untuk algoritma sha
	sha1_init(&ctx);						//inisialisasi algoritma sha dengan struct yang baru dibuat
	sha1_update(&ctx, buff, strlen(buff));	//memasukan input key untuk dicari hashnya
	sha1_final(&ctx, temp);					//menyimpan sementara hash yang baru dibuat oleh algoritma sha1 ke variabel temp
	
	
	FILE *berkaspassadmin;					//penyimpanan sementara untuk membuka file
	if ((berkaspassadmin = fopen(namafilepassadmin, "w")) != NULL)
	{
		//membuat file password admin
		int i;
		for(i=0;i<20;i++)
		{
			//menuliskan hash dari variabel temp ke file, ada 20 byte, yang ditulis dalam integer dengan pemisah karakter <,>
			if(i<19)
			{
				fprintf(berkaspassadmin,"%i,",temp[i]);
			}else
			{
				fprintf(berkaspassadmin,"%i",temp[i]);
			}
			
		}
        fclose(berkaspassadmin);	//tutup file
	}
}

void masukAdmin(BYTE *buff)
{
    //fungsi meminta sandi admin
	
    system("cls");
    printf("+++++++++++++++Masuk Admin+++++++++++++++\n");
    printf("\nSilahkan masukan sandi admin anda\n");
    printf("Jika sudah selasai, tekan <enter>\n\n");
    printf("Sandi admin anda: ");
    dapatkanInputKarakterUns(buff,16,1,0);
    system("cls");
}

void convertToKey(BYTE *input, BYTE *output)
{
	BYTE temp[SHA1_BLOCK_SIZE+1];						//penyimpanan sementara hasil hash password
	temp[20] = 0xff;									//karena diperlukan 21 byte, tetapi hasil sha1 hanya 20 byte maka ditambahkan byte ke 21 berupa heksadesimal ff
	
	SHA1_CTX ctx;										//inisialisasi struct untuk algoritma sha
	sha1_init(&ctx);									//inisialisasi algoritma sha dengan struct yang baru dibuat
	sha1_update(&ctx, input, strlen(input));			//memasukan input password untuk dicari hashnya
	sha1_final(&ctx, temp);								//menyimpan sementara hash yang baru dibuat oleh algoritma sha1 ke variabel temp
	
	int i;
	for(i=0;i<7;i++)
	{
		//mengubah 20 byte + 1 byte buatan sendiri, menjadi 7 byte key untuk digunakan pada algoritma des
		output[i] = temp[i] ^ temp[i+7] ^ temp[i+14];	//menggunakan operasi XOR
	}
	
}

int cekPassword(BYTE *input)
{
	int cocok = 0;													//variable hasil pencocokan
	BYTE tersimpan[SHA1_BLOCK_SIZE];								//variabel untuk hash yang sudah tersimpan dalam file
	
	//inisialisasi struct sha dan algoritma sha (sama kaya yang sebelumnya)
	BYTE temp[SHA1_BLOCK_SIZE];
	
	SHA1_CTX ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, input, strlen(input));
	sha1_final(&ctx, temp);
	
	
	FILE *berkaspassadmin;											//variable untuk buka file
	char pembacaan[80];												//variable mentah hasil pembacaan file
	
	if ((berkaspassadmin = fopen(namafilepassadmin, "rb")) != NULL) 
	{
		//apabila file berhasil dibuka
		fseek(berkaspassadmin, 0, SEEK_SET);						//pindahkan kursor pembacaan ke bagian awal file
		fread(pembacaan, 79, 1, berkaspassadmin);					//baca hingga 79 karakter, lalu simpan di variable pembacaan
		fclose(berkaspassadmin); 									//tutup file
		
		const char pemisah[2] = ",";								//karakter pemisah data(coba buka filenya kalau pengen tahu)
		char *cari;													//pointer untuk menyimpan hasil pencarian
		int counter1 = 0;											//counter untuk indexing
		
		cari = (char *) malloc(3);									//alokasikan memori untuk menyimpan hasil pencarian
		cari = strtok(pembacaan, pemisah);							//cari data yang dipisahkan karakter <,>
		while( cari != NULL )
	    {
	        //selama belum habis,cari data lain
	        tersimpan[counter1] = atoi(cari);						//simpan data yang didapat, dan ubah datanya dari karakter ke integer dengan fungsi atoi
	        cari = strtok(NULL, pemisah);							//cari lagi
	        counter1++;												//naikan index
	    }
		free(cari);													//kalau sudah selesai mencari jangan lupa bersihkan memori
	}
	
	
	int i;
	for(i=0;i<20;i++)
	{
		cocok += temp[i] - tersimpan[i];							//mencocokan hash yang baru diinput dengan hash dari data file, kalau ada perbedaan nilai cocok bertambah
	}
	
	if(cocok == 0)
	{
		return 1;													//kalau nilai cocok = 0 maka hash cocok, berarti password sesuai
	}else {
		return 0;
	}
	
}

void dapatkanPass(char *nama, BYTE *pass, int nomor)
{
	FILE *berkasdaftarpass;	//variable penyimpanan sementara file yang akan dibuka
	char *barisnama;		//variable penyimpanan address dari nama identitas password
	char *barispass;		//variable penyimpanan address dari password yang masih dienkripsi
	char pembacaan[75];		//variable hasil pembacaan mentah file
	
	if ((berkasdaftarpass = fopen(namafiledaftarpassword[nomor], "rb")) != NULL) 
	{
		//jika file berhasil dibuka
		fseek(berkasdaftarpass, 0, SEEK_SET);		//pindahkan kursor ke awal
		fread(pembacaan, 74, 1, berkasdaftarpass);	//baca 74 karakter
		fclose(berkasdaftarpass); 					//tutup file
		
		barisnama = strchr(pembacaan,'\n')+1;		//cari address mulainya variabel nama identitas password, yaitu setelah karakter newline(\n) pertama
		strncpy(nama,barisnama,10);					//copy nama identitas password ke variabel nama dengan address yang sudah didapat, sejumlah 10 karakter
		nama[10] = '\0';							//tambahkan karakter ke-11 berupa null, untuk mengakhiri string
		
		barispass = strrchr(pembacaan, '\n')+1;		//cari address mulainya variabel password, yaitu setelah karakter newline(\n) terakhir
		
		//cara pemisahan dan penyimpanan nilai variabel dari file dengan pemisah karakter <,>, sama seperti yang sebelumnya
		const char pemisah[2] = ",";
		char buffer1[64];
		char *cari;
		int counter1 = 0;
		
		strncpy(buffer1, barispass, 64);
		
		cari = (char *) malloc(3);
		cari = strtok(buffer1, pemisah);
		while( cari != NULL )
	    {
	        //selama belum habis,cari data lain
	        pass[counter1] = atoi(cari);
	        cari = strtok(NULL, pemisah);
	        counter1++;
	        if(counter1 == 16)
	        {
	        	break;
			}
	    }
		free(cari);
	}
	
}

void decryptPassword(BYTE *pass, BYTE *key)
{
	BYTE schedule[16][6];			//variable penyimpan bagian pecahan key algoritma des
	BYTE pt1[DES_BLOCK_SIZE];		//variable penyimpan data sebelum didekripsi
	BYTE pt2[DES_BLOCK_SIZE];
	BYTE passPt1[DES_BLOCK_SIZE];	//variable penyimpan password setelah dekripsi
	BYTE passPt2[DES_BLOCK_SIZE];
	
	int i;
	for(i=0;i<8;i++)
	{
		//karena algoritma des hanya bisa mengerjakan 8 byte pada satu waktu, maka harus dibagi menjadi dua bagian
		pt1[i] = pass[i];
		pt2[i] = pass[i+8];
	}
	
	des_key_setup(key, schedule, DES_DECRYPT);	//menyiapkan bagian pecahan key untuk proses dekripsi
	des_crypt(pt1, passPt1, schedule);			//menjalankan dekripsi dengan bagian pecahan key, bagian 1
	des_crypt(pt2, passPt2, schedule);			//menjalankan dekripsi dengan bagian pecahan key, bagian 2
	
	for(i=0;i<16;i++)
	{
		//menggabungkan lagi menjadi satu bagian
		if(i<8)
		{
			pass[i] = passPt1[i];
		}else
		{
			pass[i] = passPt2[i-8];
		}
	}
	
}

int menuPassword(BYTE *key)
{
	int menu_password;							//variable output pilihan menu
    do
    {
    	char nama1[11], nama2[11], nama3[11];	//variabel nama pengenal password
    	BYTE pass1[16], pass2[16], pass3[16];	//variabel password
    	
    	dapatkanPass(nama1, pass1, 0);			//dapatkan password yang masih terenkripsi dari file
    	dapatkanPass(nama2, pass2, 1);
    	dapatkanPass(nama3, pass3, 2);
    	
    	decryptPassword(pass1,key);				//buka enkripsi password dengan key
    	decryptPassword(pass2,key);
    	decryptPassword(pass3,key);
        
        
        //menampilkan password tersimpan
        system("cls"); //bersihkan layar
        printf("+++++++++++++++Password Tersimpan+++++++++++++++\n\n"); //tampilkan menu
        printf("Login : %s  Password : \"", nama1);
        int i;
        for(i=0;i<16;i++)
        {
        	if(pass1[i] == ' ')
        	{
        		break; //kalau password berisi karakter <spasi> berarti password sudah semuanya ditampilkan(tidak sampai 16 karakter)
			}
			printf("%c", pass1[i]);
		}
		printf("\0");
		printf("\"\n");
		
        printf("Login : %s  Password : \"", nama2);
        for(i=0;i<16;i++)
        {
        	if(pass2[i] == ' ')
        	{
        		break;
			}
			printf("%c", pass2[i]);
		}
		printf("\0");
		printf("\"\n");
		
        printf("Login : %s  Password : \"", nama3);
        for(i=0;i<16;i++)
        {
        	if(pass3[i] == ' ')
        	{
        		break;
			}
			printf("%c", pass3[i]);
		}
		printf("\0");
		printf("\"\n\n");
		
		printf("+++++++++++++++Menu+++++++++++++++\n\n");
        printf("1. Edit Password 1\n");
        printf("2. Edit Password 2\n");
        printf("3. Edit Password 3\n\n");
        printf("4. Keluar\n");
        printf("\nMasukan angka menu untuk memilih, lalu tekan <enter>\n\n");
        printf("Pilihan anda: ");
        
        //meminta input user, dan akan mengulang bila input yang diberikan bukan angka
        menu_password = dapatkanInputAngka();
    }while(menu_password == -1);
    system("cls"); //bersihkan layar
    if(menu_password > 4 || menu_password < -1)
    {
        //apabila input bukan pilihan yang benar maka akan menampilakn error dan mengulang perintah memasukan input
        system("cls");
    	printf("+++++++++++++++Error+++++++++++++++\n");
		printf("\n\nError : Pilihan yang anda masukan salah, silahkan masukan pilihan yang benar!\n");
        printf("Tekan tombol apa saja untuk melanjutkan\n");
        getch(); //agar program berhenti sementara
        system("cls");
        menu_password = menuPassword(key); //memanggil ulang fungsi
    }
    return menu_password;
}

void ambilDaftarPass(char *nama, BYTE *pass)
{
	system("cls");
    printf("+++++++++++++++Edit Daftar Password+++++++++++++++\n\n");
    printf("\nSilahkan masukan nama login (maksimum 10 huruf)\n");
    printf("Jika sudah selasai, tekan <enter>\n\n");
    printf("Nama login: ");
    dapatkanInputKarakter(nama,10);
    
    system("cls");
    printf("+++++++++++++++Edit Daftar Password+++++++++++++++\n");
    printf("\nSilahkan masukan password yang ingin disimpan (maksimum 16 karakter)\n");
    printf("Perhatian, password tidak boleh mengandung karakter spasi\n");
    printf("Jika sudah selasai, tekan <enter>\n\n");
    printf("Password: ");
    dapatkanInputKarakterUns(pass,16,0,1);
}

void encryptPassword(BYTE *pass, BYTE *key)
{
	//penjelasan : kebalikan proses dekripsi
	BYTE schedule[16][6];
	BYTE passPt1[DES_BLOCK_SIZE];
	BYTE passPt2[DES_BLOCK_SIZE];
	BYTE pt1[DES_BLOCK_SIZE];
	BYTE pt2[DES_BLOCK_SIZE];
	
	int i;
	for(i=0;i<8;i++)
	{
		passPt1[i] = pass[i];
		passPt2[i] = pass[i+8];
	}
	
	des_key_setup(key, schedule, DES_ENCRYPT);
	des_crypt(passPt1, pt1, schedule);
	des_crypt(passPt2, pt2, schedule);
	
	for(i=0;i<16;i++)
	{
		if(i<8)
		{
			pass[i] = pt1[i];
		}else
		{
			pass[i] = pt2[i-8];
		}
	}
}

void createDaftarPassFile(char *nama, BYTE *pass, int nomor)
{
	FILE *berkasDaftarPass;	
	if ((berkasDaftarPass = fopen(namafiledaftarpassword[nomor], "w")) != NULL)
	{
		//buka file, hapus data lama, timpa dengan data baru
		int i;
		fprintf(berkasDaftarPass,"\n");
		for(i=0;i<10;i++)
		{
			fprintf(berkasDaftarPass,"%c",nama[i]);	//tulis nama identitas password
		}
		fprintf(berkasDaftarPass,"\n");
		for(i=0;i<16;i++)
		{
			//tulis password yang sudah dienkripsi, dengan pemisah karakter <,>
			if(i<15)
			{
				fprintf(berkasDaftarPass,"%i,",pass[i]);
			}else
			{
				fprintf(berkasDaftarPass,"%i",pass[i]);
			}
			
		}
        fclose(berkasDaftarPass);	//tutup file
	}
}
