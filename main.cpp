#include<iostream>
#include<string>
#include<Windows.h>
#include"PeAnalyis.h"

int main() {
	std::string path;
	std::cout << "Welcome to the file analyis system" << std::endl;
	std::cout << "Please input a pe filepath: ";
	std::getline(std::cin,path); std::cout << std::endl;
	//path = "D:\\PCL\\PCL\\libwebp.dll";
	PeAnalyis file1(path.c_str());
	if (!file1.analyisfile()) { 
		std::cout << "Failed to analyis file" << std::endl;
		file1.errorcheck();
	}
	system("pause");
}