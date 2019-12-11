/*
   Credits to Brad Conte for his crypto-algorithms. sha1 and des library.
   Credits to http://www.anyexample.com/programming/c/qsort__sorting_array_of_strings__integers_and_structs.xml for the sorting example
*/

#include <stdio.h>
#include <memory.h>
#include <string.h>
#include<stdlib.h>
#include<conio.h>
#include "sha1.h"
#include "des.h"
#include "windows.h"

//COLOR
#define ANSI_COLOR_MAGENTA "\033[0;35m"
#define ANSI_COLOR_BOLD_MAGENTA "\033[1;35m"

#define ANSI_COLOR_BLUE "\033[0;34m"
#define ANSI_COLOR_BOLD_BLUE "\033[1;34m"

#define ANSI_COLOR_CYAN "\033[0;36m"
#define ANSI_COLOR_BOLD_CYAN "\033[1;36m"

#define ANSI_COLOR_YELLOW "\033[0;33m"
#define ANSI_COLOR_BOLD_YELLOW "\033[1;33m"

#define ANSI_COLOR_GREEN "\033[0;32m"
#define ANSI_COLOR_BOLD_GREEN "\033[1;32m"

#define ANSI_COLOR_RESET "\033[0m"


//KEY
#define ARROW_LEFT 75
#define ARROW_RIGHT 77
#define ARROW_UP 72
#define ARROW_DOWN 80
#define KEY_ENTER 13

//SCREEN SETTINGS
int SCREEN_WIDHT = 120;
int SCREEN_HEIGHT = 30;

//global variable
char namafilepassadmin[] = "pass_admin.txt"; //nama file untuk menyimpan password admin
char namafiledaftar[16] = {"data_pass.txt"}; //nama file untuk menyimpan daftar password

//struct untuk enkripsi file
struct node {
   BYTE data;
   struct node *next;
};

struct node *front = NULL;
struct node *front1 = NULL;
struct node *rear = NULL;

//struct untuk menyimpan nama file
struct nodeNama {
   char namaFilePass[30];
   struct nodeNama *next;
};

struct nodeNama *frontNama = NULL;
struct nodeNama *front1Nama = NULL;
struct nodeNama *rearNama = NULL;

struct pass_struct { 
    char nama[11];
    BYTE pass[16];
};

struct user_data{
    char name[16];
    int  name_count;

    int  time;
    int  time_count;
} user;

//Prototyping

//fungsi fungsi modular untuk pencarian password
void findPassword(BYTE *key, char *kataKunci);					//mencari password yang sesuai dengan kata kunci
int structCariNama(const void *a, const void *b) ;				//fungsi pembanding data untuk pencarian
void ambilNamaPencarian(char *nama);							//mengambil kata kunci dari user untuk pencarian

//fungsi fungsi modular untuk sorting password
void sortPassword(BYTE *key);									//melakukan sorting daftar password
int structCmpNama(const void *a, const void *b);				//fungsi pembanding data untuk sorting
void printStruct(struct pass_struct *array, size_t panjang);	//untuk menampilkan hasil sorting

//fungsi fungsi modular untuk penyimpanan jumlah password dynamic
void hapusFileNamaPass(int nomor);							//menghapus nama file password dari list nama di dalam file list
void tambahFileNamaPass(int nomor);							//menambahkan nama file password dari list nama di dalam file list
void dapatkanFileNamaPass();								//mendapatkan daftar nama file password yang tersimpan di dalam file list
void requeNama();											//mengulang queue
void enqueNama(char *namaFile);								//menyimpan nama file password dalam queue
void queueNama(char *nama, int posisi);						//mendapatkan nama file dalam queue pada posisi queue tertentu
int panjangQueueNama();										//mendapatkan panjang queue

void reque();												//mengulang queue
void enque(BYTE data);										//menyimpan data unsigned char dari pembacaan file pada queue
BYTE deque();												//melakukan operasi deque untuk data file
int panjangQueue();											//mendapatkan panjang queue
int bacaFile(char *namaFIle);								//membaca file dalam bentuk biner dan memanggil fungsi queue untuk menyimpan
void encryptFile(char *namaFIle, BYTE *key);				//menginkripsi data yang sudah tersimpan dalam queue dan menyimpannya dalam sebuah file
void dapatkanPathFileRaw(char *output);						//mendapatkan path dari file yang akan dienkripsi
void convertPathFileCrypt(char *input, char *output);		//mengubah nama file input untuk ditambahkan ekstensi nama file .crypt
void dapatkanPathFileCrypt(char *output);					//mendapatkan path dari file yang akan didekripsi
void convertPathFileRaw(char *input, char *output);			//mengubah nama file untuk menghilangkan ekstensi .crypt
void decryptFile(char *namaFIle, BYTE *key);				//medekripsi data yang sudah tersimpan dalam queue dan menyimpannya dalam sebuah file

void dapatkanInputKarakter(char *output, int jumlah);							//mendapatkan input dari user berupa karakter, menghasilkan output char
void dapatkanInputKarakterUns(BYTE *output, int jumlah, int mask, int padding);	//mendapatkan input dari user berupa karakter, menghasilkan output unsigned char														//mendapatkan input dari user berupa angka, menghasilkan output integer
int cekLoginPertama();															//mengecek apakah login pertama
void createPassAdmin(BYTE *buff);												//membuat sandi admin baru
void createPassAdminFile(BYTE *buff);											//membuat file penyimpanan hash dari key (yang berasal dari password) untuk memverivikasi login selanjutnya
void masukAdmin(BYTE *buff);													//meminta password admin
void convertToKey(BYTE *input, BYTE *output);									//mengubah sandi menjadi key 7 byte untuk algoritma des
int cekPassword(BYTE *input);													//membandingkan hash dari key(yang berasala dari password) apakah sesuai dengan yang sudah tersimpan
void dapatkanPass(char *nama, BYTE *pass, int nomor);							//mendapatkan password yang masih dienkripsi dari file penyimpanan
void decryptPassword(BYTE *pass, BYTE *key);									//mendekripsi password dari penyimpanan dengan algoritma des dan key yang sesuai
int menuPassword(BYTE *key,int selection);										//menampilkan password tersimpan, dan menu utama
int menuEditPass();																//Mendapatkan input nomor password yang akan diedit
int menuHapusPass();															//Mendapatkan input nomor password yang akan dihapus
void ambilDaftarPass(char *nama, BYTE *pass);									//mengambil data nama dan password baru
void encryptPassword(BYTE *pass, BYTE *key);									//mengenkripsi password baru
void createDaftarPassFile(char *nama, BYTE *pass, int nomor);					//menyimpan password yang sudah dienkripsi ke file

void printBorderForm(char * ttl, int count1, char * str, int count2);
void printCenter(char * str, int count);
void printMenu(int i);
void gotoxy(int x, int y);

int main()
{
	getScreenSize();
	BYTE inputSandiAdmin[16];						//input password admin
	BYTE hasilKey[8];								//hasil pengolahan sha1 password sebagai key algoritma des

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
		dapatkanFileNamaPass();
		//apabila password sesuai maka masuk ke program
		while(1)
		{
			//ulangi peritah dibawah, sampai user ingin keluar
			int menu = menuPassword(hasilKey,0);		//tampilkan password tersimpan dan menu, serta dapatkan nilai hasil pilihan user
			if(menu == 1)
			{
				int pilihan_pass = menuEditPass();
				//apabila ingin mengubah password tersimpan
				char namaBaru[11]; 									//variable sementara penyimpan nama identitas password
				BYTE passBaru[16];									//variable sementara penyimpan password
				ambilDaftarPass(namaBaru, passBaru);				//meengambil data dari user
				encryptPassword(passBaru, hasilKey);				//mengenkripsi password
				createDaftarPassFile(namaBaru, passBaru, pilihan_pass-1);	//menyimpan hasil enkripsi kedalam file
			}else if(menu == 2){
				//hapus password
				int pilihan_pass1 = menuHapusPass();
				hapusFileNamaPass(pilihan_pass1-1);
			}else if(menu == 3){
				//Sort password
				sortPassword(hasilKey);
			}else if(menu == 4){
				//Cari password
				char namaPencarian[16];
				ambilNamaPencarian(namaPencarian);
				findPassword(hasilKey, namaPencarian);
			}else if(menu == 5){
				//enkripsi file
				char namafilesumber[100];
				char namafileoutput[100];
				dapatkanPathFileRaw(namafilesumber);
				convertPathFileCrypt(namafilesumber, namafileoutput);

				reque();
				int baca_sukses = bacaFile(namafilesumber);
				if(baca_sukses)
				{
					encryptFile(namafileoutput, hasilKey);
				}
			}else if(menu == 6){
				//dekripsi file
				char namafilesumber[100];
				char namafileoutput[100];
				dapatkanPathFileCrypt(namafilesumber);
				convertPathFileRaw(namafilesumber, namafileoutput);

				reque();
				int baca_sukses = bacaFile(namafilesumber);
				if(baca_sukses)
				{
					decryptFile(namafileoutput, hasilKey);
				}
			}else if(menu == 7)
			{
				break;
			}
		}
	}else
	{
		getScreenSize();
		printf("\n\n\n\n\n");
		printf(ANSI_COLOR_BOLD_CYAN);
		printCenter("Password yang anda masukan salah",17);
		printCenter("Selamat tinggal!!",0);
		printf(ANSI_COLOR_RESET);
		printf("\n");
	}


	return(0);
}


//fungsi fungsi modular

void findPassword(BYTE *key, char *kataKunci) 
{
	int panjang_daftar = panjangQueueNama();
	int j;
	char nama[11];
	BYTE pass[16];
	
	struct pass_struct daftarPass[panjang_daftar];
	
	for(j=0;j<panjang_daftar;j++)
    {
    	dapatkanPass(nama, pass, j);	//dapatkan password yang masih terenkripsi dari file
    	decryptPassword(pass,key);		//buka enkripsi password dengan key
		
		strcpy(daftarPass[j].nama,nama);
		
    	int i;
        for(i=0;i<16;i++)
        {
        	daftarPass[j].pass[i] = pass[i];
		}
	}
 
    size_t panjang_struct = sizeof(daftarPass) / sizeof(struct pass_struct);

    qsort(daftarPass, panjang_struct, sizeof(struct pass_struct), structCmpNama);
    
    struct pass_struct *pencarian;
    
    pencarian = bsearch(kataKunci, daftarPass, panjang_struct, sizeof(struct pass_struct), structCariNama);

 	if(pencarian!=NULL)
	{
		system("cls"); //bersihkan layar
	    getScreenSize();
	    printf(ANSI_COLOR_RESET);
		printf("\n");
		printf(ANSI_COLOR_BOLD_YELLOW);
	    printCenter("+++++++++++++++Password Ditemukan+++++++++++++++\n",30); //tampilkan menu
	    printf(ANSI_COLOR_RESET);
	    printf("\n");
	    
	    printf("\t\t\t\t\t\tLogin : %s \t Password : \"", pencarian->nama);
		int i;
	    for(i=0;i<16;i++)
	    {
	    	if(pencarian->pass[i] == ' ')
	    	{
	    		break; //kalau password berisi karakter <spasi> berarti password sudah semuanya ditampilkan(tidak sampai 16 karakter)
			}
			printf("%c", pencarian->pass[i]);
		}
		printf("\0");
		printf("\"\n");
	}else
	{
		system("cls"); //bersihkan layar
	    getScreenSize();
	    printf(ANSI_COLOR_RESET);
		printf("\n");
		printf(ANSI_COLOR_BOLD_YELLOW);
	    printCenter("+++++++++++++++Password Tidak Ditemukan+++++++++++++++\n",30); //tampilkan menu
	    printf(ANSI_COLOR_RESET);
	    printf("\n");
	} 	
    
    getScreenSize();
	printf(ANSI_COLOR_BOLD_BLUE);
    printf("\n\n");
	printCenter("Tekan apa saja untuk melanjutkan",20);
	getch();
}

int structCariNama(const void *a, const void *b) 
{ 
    struct pass_struct *ib = (struct pass_struct *)b;
    return strcasecmp(a, ib->nama);
} 

void ambilNamaPencarian(char *nama)
{
	getScreenSize();
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_CYAN);
    printCenter("+++++++++++++++Cari Password+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
	printf("\n\n");
    printCenter("Silahkan masukan nama login yang ingin dicari (maksimum 10 huruf)",35);
    printCenter("Jika sudah selasai, tekan <enter>",20);
    printf("\n");
    printCenter("Nama pencarian login: ",42);
    gotoxy(SCREEN_WIDHT/2+ user.name_count/2, 11);
    dapatkanInputKarakterUns(nama,10,0,0);
    
    int i;
    int flag = 0;
    for(i=0;i<11;i++)
    {
    	if(nama[i] == '\0')
    	{
    		flag = 1;
		}
		if(flag == 1)
		{
			if(i == 10){
				nama[i] = '\0';
			}else
			{
				nama[i] = ' ';
			}
		}
	}
}


void sortPassword(BYTE *key) 
{
	int panjang_daftar = panjangQueueNama();
	int j;
	char nama[11];
	BYTE pass[16];
	
	struct pass_struct daftarPass[panjang_daftar];
	
	for(j=0;j<panjang_daftar;j++)
    {
    	dapatkanPass(nama, pass, j);	//dapatkan password yang masih terenkripsi dari file
    	decryptPassword(pass,key);		//buka enkripsi password dengan key
		
		strcpy(daftarPass[j].nama,nama);
		
    	int i;
        for(i=0;i<16;i++)
        {
        	daftarPass[j].pass[i] = pass[i];
		}
	}
 
    size_t panjang_struct = sizeof(daftarPass) / sizeof(struct pass_struct);

    qsort(daftarPass, panjang_struct, sizeof(struct pass_struct), structCmpNama);
    
    printStruct(daftarPass, panjang_struct);
    
    getScreenSize();
	printf(ANSI_COLOR_BOLD_BLUE);
    printf("\n\n");
	printCenter("Tekan apa saja untuk melanjutkan",20);
	getch();
}

int structCmpNama(const void *a, const void *b) 
{ 
    struct pass_struct *ia = (struct pass_struct *)a;
    struct pass_struct *ib = (struct pass_struct *)b;
    return strcasecmp(ia->nama, ib->nama);
} 

void printStruct(struct pass_struct *array, size_t panjang) 
{ 
	system("cls"); //bersihkan layar
    getScreenSize();
    printf(ANSI_COLOR_RESET);
	printf("\n");
	printf(ANSI_COLOR_BOLD_YELLOW);
    printCenter("+++++++++++++++Password Tersimpan+++++++++++++++\n",30); //tampilkan menu
    printf(ANSI_COLOR_RESET);
    printf("\n");
    
    int j;
 
    for(j=0; j<panjang; j++)
    {
    	printf("\t\t\t\t\t\t %d Login : %s \t Password : \"", j+1,array[j].nama);
    	int i;
        for(i=0;i<16;i++)
        {
        	if(array[j].pass[i] == ' ')
        	{
        		break; //kalau password berisi karakter <spasi> berarti password sudah semuanya ditampilkan(tidak sampai 16 karakter)
			}
			printf("%c", array[j].pass[i]);
		}
		printf("\0");
		printf("\"\n");
	}
} 


void hapusFileNamaPass(int nomor)
{
	int panjang_daftar = panjangQueueNama();
	int j;
	char nama[11];
	BYTE pass[16];
    
    for(j=0;j<panjang_daftar-1;j++)
    {
    	if(j>=nomor)
    	{
    		dapatkanPass(nama, pass, j+1);
    		createDaftarPassFile(nama, pass, j);
		}
	}
	
	FILE *berkasdaftar;
	if ((berkasdaftar = fopen(namafiledaftar, "w")) != NULL) 
	{
		for(j=0;j<panjang_daftar-2;j++)
		{
			fprintf(berkasdaftar,"data_pass_%i.txt\n",j+1);
		}
		fprintf(berkasdaftar,"data_pass_%i.txt",j+1);
		fclose(berkasdaftar);
	}
	
	requeNama();
	dapatkanFileNamaPass();
}

void tambahFileNamaPass(int nomor)
{
	FILE *berkasdaftar;
	
	if ((berkasdaftar = fopen(namafiledaftar, "a")) != NULL) 
	{
		fprintf(berkasdaftar,"\ndata_pass_%i.txt",nomor);
		fclose(berkasdaftar);
	}
	if ((berkasdaftar = fopen(namafiledaftar, "r")) != NULL) 
	{	
		char line[30];
		int count = 1;
		
		fseek(berkasdaftar, 0, SEEK_SET);
		
		while(fgets(line, sizeof(line), berkasdaftar) != NULL)
		{
			if(count == nomor)
			{
				enqueNama(line);
			}
			count++;
		}
		
		fclose(berkasdaftar);
        
	}
}

void dapatkanFileNamaPass()
{
	FILE *berkasdaftar;	//variable penyimpanan sementara file yang akan dibuka
	
	if ((berkasdaftar = fopen(namafiledaftar, "r")) != NULL) 
	{
		requeNama();
		
		char line[30];
		
		fseek(berkasdaftar, 0, SEEK_SET);
		
		while(fgets(line, sizeof(line), berkasdaftar) != NULL)
		{
			enqueNama(line);
		}
		
		fclose(berkasdaftar);
        
	}
	
}

//mereset queue nama
void requeNama()
{
	while(1)
	{
		front1Nama = frontNama;
 		
 		if (front1Nama == NULL)
	    {
	        return;
	    }else if (front1Nama->next != NULL)
	    {
	        front1Nama = front1Nama->next;
	        free(frontNama);
	        frontNama = front1Nama;
	    } else
	    {
	        free(frontNama);
	        frontNama = NULL;
	        rearNama = NULL;
	        break;
	    }
	}
}

//Membuat queue nama
void enqueNama(char *namaFile)
{
	// Allocate memory for new node;
	struct nodeNama *link = (struct nodeNama*) malloc(sizeof(struct nodeNama));
	
	int i = 0;
	while(1){
		if(namaFile[i] == '\n' || namaFile[i] == '\0')
		{
			link->namaFilePass[i] = '\0';
			break;
		}
		link->namaFilePass[i] = namaFile[i];
		i++;
	}
	
	link->next = NULL;
	
	// If head is empty, create new list
	if(frontNama==NULL) {
		frontNama = link;
		rearNama = frontNama;
		return;
	}
	
	rearNama->next = link;
	rearNama = link;
}

//Menghilangkan data depan (deque) nama
void queueNama(char *nama, int posisi)
{
	int count = 0;
	front1Nama = frontNama;
 
    if ((front1Nama == NULL) && (rearNama == NULL))
    {
        return;
    }
    
    while (front1Nama != rearNama)
    {
    	if(count == posisi)
		{
    		int i = 0;
			while(1)
			{
				if(front1Nama->namaFilePass[i] == '\0')
				{
					nama[i] = '\0';
					break;
				}
				nama[i] = front1Nama->namaFilePass[i];
				i++;
			}
			return;
		}
        count++;
        front1Nama = front1Nama->next;
    }
    
    if (front1Nama == rearNama)
    {
    	int i = 0;
		while(1)
		{
			if(front1Nama->namaFilePass[i] == '\0')
			{
				nama[i] = '\0';
				break;
			}
			nama[i] = front1Nama->namaFilePass[i];
			i++;
		}
	}
}

int panjangQueueNama()
{
	int panjang = 0;
	front1Nama = frontNama;
 
    if ((front1Nama == NULL) && (rearNama == NULL))
    {
        return 0;
    }
    
    while (front1Nama != rearNama)
    {
        panjang++;
        front1Nama = front1Nama->next;
    }
    
    if (front1Nama == rearNama)
        panjang++;
	
	return panjang;
}

//mereset queue
void reque()
{
	front = NULL;
	rear = NULL;
}

//Membuat queue
void enque(BYTE data)
{
	// Allocate memory for new node;
	struct node *link = (struct node*) malloc(sizeof(struct node));

	link->data = data;
	link->next = NULL;

	// If head is empty, create new list
	if(front==NULL) {
		front = link;
		rear = front;
		return;
	}

	rear->next = link;
	rear = link;
}

//Menghilangkan data depan (deque)
BYTE deque()
{
    front1 = front;

    if (front1 == NULL)
    {
        return 0;
    } else if (front1->next != NULL)
    {
        front1 = front1->next;
        BYTE data = front->data;
        free(front);
        front = front1;
        return data;
    } else
    {
		BYTE data = front->data;
        free(front);
        front = NULL;
        rear = NULL;
        return data;
    }
}

int panjangQueue()
{
	int panjang = 0;
	front1 = front;

    if ((front1 == NULL) && (rear == NULL))
    {
        return 0;
    }

    while (front1 != rear)
    {
        panjang++;
        front1 = front1->next;
    }

    if (front1 == rear)
        panjang++;

	return panjang;
}

int bacaFile(char *namaFIle)
{
	FILE *berkas;	//variable penyimpanan sementara file yang akan dibuka
	BYTE pembacaan[1];			//variable hasil pembacaan mentah file
	BYTE data;
	long filelen;			//panjang file
	int i;

	if ((berkas = fopen(namaFIle, "rb")) != NULL)
	{
		//jika file berhasil dibuka
		fseek(berkas, 0, SEEK_END);		//pindahkan kursor ke akhir untuk melihat panjang file
		filelen = ftell(berkas);			//mencari panjang file
		rewind(berkas);					//pindahkan lagi kursor ke awal

		for(i = 0; i < filelen; i++)
		{
			//baca file per byte
		    fread(pembacaan, 1, 1, berkas);
		    data = pembacaan[0];
		    enque(data); //simpan data ke queue
		}

		fclose(berkas); 					//tutup file
		return 1;
	}else{
		getScreenSize();
		system("cls");
		printf("\n\n\n\n\n");
		printf(ANSI_COLOR_BOLD_BLUE);
	    printCenter("+++++++++++++++File Tidak Ditemukan+++++++++++++++",40);
	    printf(ANSI_COLOR_RESET);
	    printf("\n\n");
		printCenter("File tidak ditemukan, silahkan ulangi dengan path yang benar",45);
		printCenter("Tekan apa saja untuk melanjutkan",20);
		printf("\n");
		getch();

		return 0;
	}

}

void encryptFile(char *namaFIle, BYTE *key)
{
	BYTE schedule[16][6];
	BYTE dataRaw[DES_BLOCK_SIZE];
	BYTE dataCrypt[DES_BLOCK_SIZE];

	FILE *berkas;	//variable penyimpanan sementara file yang akan dibuka

	int i,j,k;
	int panjang = panjangQueue();
	int iterasi = panjang / 8;
	int data_left = panjang - iterasi*8;
	int panjang_padding = 8 - data_left;

	if(data_left){
		iterasi++;
	}

	des_key_setup(key, schedule, DES_ENCRYPT);

	if ((berkas = fopen(namaFIle, "wb")) != NULL)
	{
		fprintf(berkas,"%c",panjang_padding);	//tulis panjang padding

		for(i=0;i<iterasi;i++)
		{
			for(j=0;j<8;j++)
			{
				dataRaw[j] = deque();
			}
			des_crypt(dataRaw, dataCrypt, schedule);
			for(k=0;k<8;k++)
			{
				fprintf(berkas,"%c",dataCrypt[k]);
			}
		}
		fclose(berkas);	//tutup file
	}
	getScreenSize();
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_BOLD_MAGENTA);
    printCenter("+++++++++++++++File Terenkripsi+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
    printf("\n\n");
	printCenter("File telah berhasil terenkripsi",20);
	printCenter("\n\nTekan apa saja untuk melanjutkan",20);
	printf("\n");
	getch();
}

void dapatkanPathFileRaw(char *output)
{
	getScreenSize();
	char temp[100];
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_BOLD_YELLOW);
    printCenter("+++++++++++++++Path File+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
    printf("\n\n");
	printCenter("Masukan path file yang ingin dienkripsi",40);
	printCenter("Misal \"D:\\ridho\\Desktop\\test file.txt\" tanpa tanda kutip",55);
	printf("\n");
	printCenter("Path : ",30);
    gotoxy(SCREEN_WIDHT/2 + user.name_count/2, 11);
	gets(temp);
	int i = 0, j = 0;
	while(1){
		if(temp[i] != '\0'){
			if(temp[i] != '\\')
			{
				output[j] = temp[i];
			}else
			{
				output[j] = '\\';
				j++;
				output[j] = '\\';
			}
			j++;
			i++;
		}else
		{
			break;
		}
	}
	output[j] = '\0';
}

void convertPathFileCrypt(char *input, char *output)
{
	int i = 0;
	while(1)
	{
		if(input[i] != '\0')
		{
			output[i] = input[i];
			i++;
		}else
		{
			break;
		}
	}
	output[i] = '.';
	i++;
	output[i] = 'c';
	i++;
	output[i] = 'r';
	i++;
	output[i] = 'y';
	i++;
	output[i] = 'p';
	i++;
	output[i] = 't';
	i++;
	output[i] = '\0';
}

void dapatkanPathFileCrypt(char *output)
{
	getScreenSize();
	char temp[100];
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_BOLD_YELLOW);
    printCenter("+++++++++++++++Path File+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
    printf("\n\n");
	printCenter("Masukan path file yang ingin didekripsi",40);
	printCenter("Misal \"D:\\ridho\\Desktop\\test file.txt.crypt\" tanpa tanda kutip",55);
	printf("\n");
	printCenter("Path : ",30);
	gotoxy(SCREEN_WIDHT/2 + user.name_count/2, 11);
	gets(temp);
	int i = 0, j = 0;
	while(1){
		if(temp[i] != '\0'){
			if(temp[i] != '\\')
			{
				output[j] = temp[i];
			}else
			{
				output[j] = '\\';
				j++;
				output[j] = '\\';
			}
			j++;
			i++;
		}else
		{
			break;
		}
	}
	output[j] = '\0';
}

void convertPathFileRaw(char *input, char *output)
{
	int i = 0;
	while(1)
	{
		if(input[i] != '\0')
		{
			i++;
		}else
		{
			break;
		}
	}

	i -= 6;
	output[i] = '\0';
	i--;

	while(1)
	{
		if(i > -1)
		{
			output[i] = input[i];
			i--;
		}else
		{
			break;
		}
	}
}

void decryptFile(char *namaFIle, BYTE *key)
{
	BYTE schedule[16][6];			//variable penyimpan bagian pecahan key algoritma des
	BYTE dataCrypt[DES_BLOCK_SIZE];		//variable penyimpan data sebelum didekripsi
	BYTE dataRaw[DES_BLOCK_SIZE];	//variable penyimpan setelah dekripsi

	FILE *berkas;	//variable penyimpanan sementara file yang akan dibuka

	int i,j,k;
	int panjang = panjangQueue();
	int iterasi = panjang / 8;

	int panjang_padding = deque();

	des_key_setup(key, schedule, DES_DECRYPT); //menyiapkan bagian pecahan key untuk proses dekripsi

	if ((berkas = fopen(namaFIle, "wb")) != NULL)
	{
		for(i=0;i<iterasi;i++)
		{
			for(j=0;j<8;j++)
			{
				dataCrypt[j] = deque();
			}
			des_crypt(dataCrypt, dataRaw, schedule);
			for(k=0;k<8;k++)
			{
				if(i == iterasi-1)
				{
					if(k == 8 - panjang_padding)
					{
						break;
					}
				}
				fprintf(berkas,"%c",dataRaw[k]);
			}
		}
		fclose(berkas);	//tutup file
	}
	getScreenSize();
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_BOLD_MAGENTA);
    printCenter("+++++++++++++++File Terdekripsi+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
	printf("\n\n");
	printCenter("File telah berhasil terdekripsi",30);
	printCenter("Tekan apa saja untuk melanjutkan",31);
	printf("\n");
	getch();

}


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
	getScreenSize();
	system("cls");
    printCenter("+++++++++++++++Pendaftaran+++++++++++++++",35);
    printf("\n\n");
    printCenter("Anda terdeteksi belum pernah menjalankan program ini!",100);
    printCenter("Silahkan masukan sandi admin baru (maksimal 16 karakter)",100);
    printCenter("Jika sudah selasai, tekan <enter>",100);
	printf(ANSI_COLOR_YELLOW);
    printBorderForm(" PASSWORD ",9, user.name, user.name_count);
    printf(ANSI_COLOR_RESET);
    gotoxy(SCREEN_WIDHT/2.5 + user.name_count/2, 7);
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
	getScreenSize();
    system("cls");
    printCenter("+++++++++++++++Masuk Admin+++++++++++++++",30);
    printf("\n\n");
	printCenter("Silahkan masukan sandi admin anda",100);
    printCenter("Jika sudah selasai, tekan <enter>",100);
    printf("\n");
    printf(ANSI_COLOR_BOLD_YELLOW);
    printBorderForm(" PASSWORD ",9, user.name, user.name_count);
    printf(ANSI_COLOR_RESET);
    gotoxy(SCREEN_WIDHT/2.5+ user.name_count/2, 7);
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
	output[i] = 0;

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
	char namafile[20];
	
	queueNama(namafile,nomor);
//	dequeNama(namafile);
	
	if ((berkasdaftarpass = fopen(namafile, "rb")) != NULL) 
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

int menuPassword(BYTE *key,int selection)
{
	getScreenSize();
	int menu_password;							//variable output pilihan menu
    do
    {
		int panjang_daftar = panjangQueueNama();
    	int j;
    	char nama[11];
    	BYTE pass[16];


        //menampilkan password tersimpan
        system("cls"); //bersihkan layar
        getScreenSize();
        printf(ANSI_COLOR_RESET);
		printf("\n");
		printf(ANSI_COLOR_BOLD_YELLOW);
        printCenter("+++++++++++++++Password Tersimpan+++++++++++++++\n",30); //tampilkan menu
        printf(ANSI_COLOR_RESET);
        printf("\n");
		
		for(j=0;j<panjang_daftar;j++)
        {
        	dapatkanPass(nama, pass, j);	//dapatkan password yang masih terenkripsi dari file
        	decryptPassword(pass,key);		//buka enkripsi password dengan key
			printf("\t\t\t\t\t\t %d Login : %s \t Password : \"", j+1,nama);
        	int i;
	        for(i=0;i<16;i++)
	        {
	        	if(pass[i] == ' ')
	        	{
	        		break; //kalau password berisi karakter <spasi> berarti password sudah semuanya ditampilkan(tidak sampai 16 karakter)
				}
				printf("%c", pass[i]);
			}
			printf("\0");
			printf("\"\n");
		}

	printf(ANSI_COLOR_BOLD_CYAN);
	printCenter("++++++++++++++++++++ Menu +++++++++++++++++++++\n",30);
	printf(ANSI_COLOR_RESET);
	printMenu(selection);

    int is_on_menu = 1;
    while (is_on_menu){
        if (kbhit()){
            char c = getch();
            int is_refresh = 1;
            switch (c){
                case ARROW_UP:
                    selection--;
                    break;

                case ARROW_DOWN:
                    selection++;
                    break;

                case KEY_ENTER:
                    is_on_menu = 0;
                    is_refresh = 0;
                    break;

                default:
                    is_refresh = 0;
                    break;
            }
            if (selection > 6)
                selection = 0;

            if (selection < 0)
                selection = 6;

            if (is_refresh)
                printMenu(selection);
        }
    }

	//KEY_ENTER is pressed
    switch (selection){
        case 0:
            menu_password=1;
            break;

        case 1:
            menu_password=2;
            break;

        case 2:
          	menu_password=3;
            break;

        case 3:
            menu_password=4;
            break;

        case 4:
            menu_password=5;
            break;
            
        case 5:
            menu_password=6;
            break;
            
        case 6:
            menu_password=7;
            break;

        default:
         break;

    }
}
        //meminta input user, dan akan mengulang bila input yang diberikan bukan angka
    while(menu_password == -1);
    system("cls"); //bersihkan layar
    if(menu_password > 7 || menu_password < -1)
    {
        //apabila input bukan pilihan yang benar maka akan menampilakn error dan mengulang perintah memasukan input
        getScreenSize();
        system("cls");
        printf("\n\n\n\n\n");
    	printCenter("+++++++++++++++Error+++++++++++++++",40);
		printCenter("Error : Pilihan yang anda masukan salah, silahkan masukan pilihan yang benar!",55);
        printCenter("Tekan tombol apa saja untuk melanjutkan\n",30);
        getch(); //agar program berhenti sementara
        system("cls");
        menu_password = menuPassword(key,0); //memanggil ulang fungsi
    }
    return menu_password;
}

int menuEditPass()
{
	int menu_password;							//variable output pilihan menu
    do
    {
        //menampilkan password tersimpan
        getScreenSize();
        system("cls"); //bersihkan layar
        printf("\n\n\n\n\n");
        printf(ANSI_COLOR_BOLD_YELLOW);
        printCenter("+++++++++++++++Edit Password+++++++++++++++",40); //tampilkan menu
		printf(ANSI_COLOR_RESET);
		printf("\n\n");
        printCenter("Masukan angka nomor daftar password yang ingin diedit",35);
        printCenter("Masukan angka lain bila ingin menambah password baru, lalu tekan <enter>",55);
        printf("\n");
        printCenter("Pilihan anda: ",30);
        gotoxy(SCREEN_WIDHT/2+ user.name_count/2, 11);
        
        //meminta input user, dan akan mengulang bila input yang diberikan bukan angka
        menu_password = dapatkanInputAngka();
    }while(menu_password == -1);
    system("cls"); //bersihkan layar
    if(menu_password > 9 || menu_password < -1)
    {
        //apabila input bukan pilihan yang benar maka akan menampilakn error dan mengulang perintah memasukan input
        getScreenSize();
        system("cls");
        printf("\n\n\n\n\n");
        printf(ANSI_COLOR_BOLD_GREEN);
    	printCenter("+++++++++++++++Error+++++++++++++++",35);
    	printf(ANSI_COLOR_RESET);
    	printf("\n\n");
		printCenter("Error : Pilihan yang anda masukan salah, silahkan masukan pilihan yang benar!",75);
		printf("\n");
        printCenter("Tekan tombol apa saja untuk melanjutkan",35);
        getch(); //agar program berhenti sementara
        system("cls");
        menu_password = menuEditPass(); //memanggil ulang fungsi
    }
    return menu_password;
}

int menuHapusPass()
{
	int menu_password;							//variable output pilihan menu
    do
    {
        //menampilkan password tersimpan
        getScreenSize();
        system("cls"); //bersihkan layar
        printf("\n\n\n\n\n");
        printf(ANSI_COLOR_BOLD_BLUE);
        printCenter("+++++++++++++++Hapus Password+++++++++++++++",35); //tampilkan menu
		printf(ANSI_COLOR_RESET);
		printf("\n\n");
        printCenter("Masukan angka nomor daftar password yang ingin dihapus, lalu tekan <enter>",55);
        printf("\n");
        printCenter("Pilihan anda: ",30);
        gotoxy(SCREEN_WIDHT/2+ user.name_count/2, 10);
        
        //meminta input user, dan akan mengulang bila input yang diberikan bukan angka
        menu_password = dapatkanInputAngka();
    }while(menu_password == -1);
    system("cls"); //bersihkan layar
    if(menu_password > 9 || menu_password < -1)
    {
        //apabila input bukan pilihan yang benar maka akan menampilakn error dan mengulang perintah memasukan input
        system("cls");
    	 getScreenSize();
        system("cls");
        printf("\n\n\n\n\n");
        printf(ANSI_COLOR_BOLD_MAGENTA);
    	printCenter("+++++++++++++++Error+++++++++++++++",35);
    	printf(ANSI_COLOR_RESET);
    	printf("\n\n");
		printCenter("Error : Pilihan yang anda masukan salah, silahkan masukan pilihan yang benar!",75);
		printf("\n");
        printCenter("Tekan tombol apa saja untuk melanjutkan",35);
        getch(); //agar program berhenti sementara
        system("cls");
        menu_password = menuHapusPass(); //memanggil ulang fungsi
    }
    return menu_password;
}

void ambilDaftarPass(char *nama, BYTE *pass)
{
	getScreenSize();
	system("cls");
	printf("\n\n\n\n\n");
	printf(ANSI_COLOR_CYAN);
    printCenter("+++++++++++++++Edit Daftar Password+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
	printf("\n\n");
    printCenter("Silahkan masukan nama login (maksimum 10 huruf)",35);
    printCenter("Jika sudah selasai, tekan <enter>",20);
    printf("\n");
    printCenter("Nama login: ",30);
    gotoxy(SCREEN_WIDHT/2+ user.name_count/2, 11);
    dapatkanInputKarakter(nama,10);
	
	getScreenSize();
    system("cls");
    printf("\n\n\n\n\n");
    printf(ANSI_COLOR_CYAN);
    printCenter("+++++++++++++++Edit Daftar Password+++++++++++++++",40);
    printf(ANSI_COLOR_RESET);
    printf("\n\n");
    printCenter("Silahkan masukan password yang ingin disimpan (maksimum 16 karakter)",50);
    printCenter("Perhatian, password tidak boleh mengandung karakter spasi",35);
    printCenter("Jika sudah selasai, tekan <enter>",20);
    printf("\n");
    printCenter("Password: ",30);
    gotoxy(SCREEN_WIDHT/2+ user.name_count/2, 12);
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
	char namafile[20];
	int i;
	int panjang_daftar = panjangQueueNama();
	
	if(nomor<panjang_daftar)
	{
		queueNama(namafile,nomor);
	}else
	{
		tambahFileNamaPass(panjang_daftar+1);
		queueNama(namafile,panjang_daftar);
	}
	
	FILE *berkasDaftarPass;	
	if ((berkasDaftarPass = fopen(namafile, "w")) != NULL)
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


void printBorderForm(char * ttl, int count1, char * str, int count2){
    int widht = 28;
    int line;
    int i;
    for (line = 0; line < 3; line++){
        if (line == 0 ||line == 2){
            for (i = 0; i < SCREEN_WIDHT; i++){
                if ((SCREEN_WIDHT - widht)/2 + widht < i)
                    break;
                else if (line == 0 && (SCREEN_WIDHT - count1)/ 2 <= i && i < (SCREEN_WIDHT - count1)/2 + count1)
                    printf("%c", ttl[i - (SCREEN_WIDHT - count1)/ 2]);
                else if ((SCREEN_WIDHT - widht)/ 2 <= i + 1){
                    if ((SCREEN_WIDHT - widht)/ 2 == i + 1 || (SCREEN_WIDHT - widht)/2 + widht == i)
                        printf("+");
                    else
                        printf("-");
                } else
                    printf(" ");
            }
        } else {
            for (i = 0; i < SCREEN_WIDHT; i++){
                if ((SCREEN_WIDHT - widht)/2 + widht < i){
                    break;
                } else if ((SCREEN_WIDHT - count2)/ 2 <= i && i < (SCREEN_WIDHT - count2)/2 + count2)
                    printf("%c", str[i - (SCREEN_WIDHT - count2)/ 2]);
                else if ((SCREEN_WIDHT - widht)/ 2 == i + 1 || (SCREEN_WIDHT - widht)/2 + widht == i)
                        printf("|");
                else
                    printf(" ");
            }
        }
        printf("\n");
    }
    printf("\n");
}

void printCenter(char * str, int count){
	int i;
    for ( i = 0; i < SCREEN_WIDHT; i++){
        if ((SCREEN_WIDHT - count)/ 2 <= i){
            printf("%s\n", str);
            break;
        } else
            printf(" ");
    }
}



void gotoxy(int x, int y){
    HANDLE hConsoleOutput;
    COORD dwCursorPosition;
    dwCursorPosition.X = x;
    dwCursorPosition.Y = y;
    hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleCursorPosition(hConsoleOutput,dwCursorPosition);
}



int getScreenSize(){
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    int columns, rows;

    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    SCREEN_WIDHT = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    SCREEN_HEIGHT = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
}


void printMenu(int i){
    gotoxy(0, 8);
printf("\n\n");
    if (i == 0)
        printf(ANSI_COLOR_BOLD_GREEN);
    if (user.time == 0)
        printCenter("Edit Pass \n\n",0);
    if (i == 0)
        printf(ANSI_COLOR_RESET);

    if (i == 1)
    	printf(ANSI_COLOR_BOLD_GREEN);
    printCenter("Hapus Pass \n\n",0);
    if (i == 1)
        printf(ANSI_COLOR_RESET);
	
	if (i == 2)
    	printf(ANSI_COLOR_BOLD_GREEN);
    printCenter("Sort Pass \n\n",0);
    if (i == 2)
        printf(ANSI_COLOR_RESET);
        
	if (i == 3)
    	printf(ANSI_COLOR_BOLD_GREEN);
    printCenter("Cari Pass \n\n",0);
    if (i == 3)
        printf(ANSI_COLOR_RESET);

    if (i == 4)
        printf(ANSI_COLOR_BOLD_GREEN);
    printCenter("Encrypt a file\n\n", 0);
    if (i == 4)
        printf(ANSI_COLOR_RESET);


    if (i == 5)
        printf(ANSI_COLOR_BOLD_GREEN);
    printCenter("Decrypt a file\n\n",0);
    if (i == 5)
        printf(ANSI_COLOR_RESET);


    if (i == 6)
        printf(ANSI_COLOR_GREEN);
   printCenter("Keluar",0);
    if (i == 6)
        printf(ANSI_COLOR_RESET);

}

