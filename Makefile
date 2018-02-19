compile:
	javac -cp lib/dnsjava-2.1.8.jar: src/* -d ./bin

clean:
	rm -f ./bin/*

all:
	rm -f ./bin/*
	javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/* -d ./bin

dns:
	javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolver.java -d ./bin
	java -cp "bin/:lib/dnsjava-2.1.8.jar" resolver $(host) $(type)

dnssec:
	javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolversec.java -d ./bin
	java -cp "bin/:lib/dnsjava-2.1.8.jar" resolversec $(host) $(type)
