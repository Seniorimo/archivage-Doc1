package com.example.archivage_Doc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "com.example.archivage_Doc")
public class ArchivageDocApplication {

	public static void main(String[] args) {
		SpringApplication.run(ArchivageDocApplication.class, args);
	}

}
