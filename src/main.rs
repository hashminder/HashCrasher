
use bcrypt::{ verify};
use md4::{Md4, Digest};
use md5;
use ntlm_hash::{ntlm_hash};
use sha1::{Sha1};
use sha2::{Sha256, Sha512};
use core::{panic, str};
use std::fs::File;
use std::io::{self, BufRead, Read,};
use std::{fs, string};
use colored::*;
use rayon::prelude::*;
use std::path::{self, Path};

enum Ask_Status {
    Exist,
    Does_Not_Exist,
    Empty,
}

fn salty_breaker(salt_text: String) -> String {
    println!(
        "starting salty attack ...\n{}",
        "note that it only works for dictionary attack".red()
    );

    let file = File::open("wordlist.txt").expect("Failed to open wordlist.txt");
    let reader = io::BufReader::new(file);

    let file_path = "hash.txt";
    let hash_text = fs::read_to_string(file_path)
        .expect("Failed to open hash.txt")
        .trim()
        .to_string();

    for line in reader.lines() {
        let each_word = match line {
            Ok(word) => word,
            Err(_) => continue,
        };

        if str::from_utf8(&each_word.as_bytes()).is_err() {
            continue;
        }

        let guess_pass = each_word.clone(); // assumed guess_pass comes from wordlist

        // Section 1: HASH(salt + each_word)
        {
            let attempt = salt_text.clone() + &each_word;
            let guess_hash = hash_maker(&hash_type_check(&hash_text), &attempt);
            if guess_hash == hash_text {
                return each_word;
            }
        }

        // Section 2: HASH(guess_pass + salt)
        {
            let attempt = guess_pass.clone() + &salt_text;
            let guess_hash = hash_maker(&hash_type_check(&hash_text), &attempt);
            if guess_hash == hash_text {
                return guess_pass;
            }
        }

        // Section 3: Double hash before
        {
            let step1 = hash_maker(&hash_type_check(&hash_text), &guess_pass);
            let step2 = step1 + &salt_text;
            let step3 = hash_maker(&hash_type_check(&hash_text), &step2);
            if step3 == hash_text {
                return guess_pass;
            }
        }

        // Section 4: Double hash after
        {
            let step1 = hash_maker(&hash_type_check(&hash_text), &guess_pass);
            let step2 = salt_text.clone() + &step1;
            let step3 = hash_maker(&hash_type_check(&hash_text), &step2);
            if step3 == hash_text {
                return guess_pass;
            }
        }

        // Section 5: Hash salt + hash password + hash both
        {
            let step1 = hash_maker(&hash_type_check(&hash_text), &salt_text);
            let step2 = hash_maker(&hash_type_check(&hash_text), &guess_pass);
            let step3 = step1 + &step2;
            let step4 = hash_maker(&hash_type_check(&hash_text), &step3);
            if step4 == hash_text {
                return guess_pass;
            }
        }

        // Section 6: Hash password + hash salt
        {
            let step1 = hash_maker(&hash_type_check(&hash_text), &salt_text);
            let step2 = hash_maker(&hash_type_check(&hash_text), &guess_pass);
            let step3 = step2 + &step1;
            let step4 = hash_maker(&hash_type_check(&hash_text), &step3);
            if step4 == hash_text {
                return guess_pass;
            }
        }
    }

    "error".to_string()
}
fn hash_maker(hash_type: &str, entry: &str) -> String { // to make hash
    match hash_type {
        "md5" => format!("{:x}", md5::compute(entry)),
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(entry);
            format!("{:x}", hasher.finalize())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(entry);
            format!("{:x}", hasher.finalize())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(entry);
            format!("{:x}", hasher.finalize())
        }
        "md4" => {
            let mut hasher = Md4::new();
            hasher.update(entry);
            format!("{:x}",hasher.finalize())
        }
        "ntlm" => {
            let mut hasher = ntlm_hash(entry);
            return hasher;
        }
        _ => "Unsupported hash type".to_string(),
    }
}
fn hash_type_check(hashed_text: &String) -> String { //to define hash type
    let cleaned = hashed_text.trim();
    let mut custom = String::new();

    let path = Path::new("ask.txt");
    let path_b = Path::exists(path);
    if path_b == true {
    let mut file = File::open("ask.txt").expect("could not open the file");
    file.read_to_string(&mut custom);
    }
    if custom.is_empty() {
        match cleaned.len() {
        32 => "md5".to_string(),
        40 => "sha1".to_string(),
        60 => "bcrypt".to_string(),
        64 => "sha256".to_string(),
        128 => "sha512".to_string(), // Changed to SHA-512
        _ => "Unknown hash type".to_string(),
    }
    } else {
        return custom;
    }
}
fn main() {
    let supported = "supported hashes : md5,sha1,sha256,sha512,md4,ntlm".to_string();
    let menu = "how to use this tool :
    put your wordlist in the same directory as this file and name it [ wordlist.txt ]
    put your hash in a text file and name it [ hash.txt ]
    and if you want a custom hash type make a txt file and name it [ ask.txt ]and write there your custom hash type 
    ( like : md4 )
    -h : show this menu
    -br : to use bruteforce (note that it works only for numbers)
    -di : for dictionary attack
    -sh : for salted hashes ( exclude bcrypt )
    -bc : go for bcrypt ...
    Note that -bc only works for dictionary attack
    -au : automated swich
    -dh : detect hash
    -info : information about the hash
    -st ask.txt status
    --hash : make a hash
    if you have a custom hash, create a text file named < ask.txt > and write there your custom hash type name 
    hash cracker will piorize that file to its ccustom detection
    ( for example : NTLM )
    -exit : to exit the hash cracker";
    println!(r" _               _                          _     
| |__   __ _ ___| |__     ___ _ __ __ _ ___| |__  
| '_ \ / _` / __| '_ \   / __| '__/ _` / __| '_ \ 
| | | | (_| \__ \ | | | | (__| | | (_| \__ \ | | |
|_| |_|\__,_|___/_| |_|  \___|_|  \__,_|___/_| |_|");
    println!("{}","you will need two text files \nhash.txt AND wordlist.txt \nput these two files in the same directory as src and target and cargo toml\nonce you've done the ".magenta().bold());
    println!("{} \n{}",menu.white().bold(),supported.white().bold());
    let path = Path::new("ask.txt");
    let path_b = Path::exists(path);
    println!("custom hash file ( ask.txt ) status : {}",path_b.to_string().red().bold());
    let mut dictionary_attack = false;
    let mut brute_force = false;
    let mut success = false;
    let mut bcrypt_bool = false;
    let mut salty = false;
    let mut th = false;

    let file_path = "hash.txt";
    #[allow(non_snake_case)]
    let hash__text = fs::read_to_string(file_path) // hashed text in hash.txt renamed at 151
        .expect("failed to open the file ")
        .trim()
        .to_string();
    let _hash_type = hash_type_check(&hash__text);

    println!("select : ");
    let mut select = String::new();
    io::stdin().read_line(&mut select).expect("something went wrong");
    
    // select operating mode 
    if select.trim() == "-di" {
        dictionary_attack = true;
        success = false;
    }
    if select.trim() == "-br" {
        brute_force = true;
        success = false;
    }
    if select.trim() == "-au" {
        brute_force = true;
        dictionary_attack = true;
        success = false;
    }
    if select.trim() == "-h" {
        println!("{}",menu);
    }
    if select.trim() == "-tr" {
        dictionary_attack = true;
        success = false;
        th = true;
    }
    if select.trim() == "-dh" {
        let hash_type = hash_type_check(&hash__text);
        println!("your hash contains a [ {} ] hash",hash_type.yellow());
    }
    if select.trim() == "-info" {
    println!("hash text has {} lengh",&hash__text.len().to_string().cyan()); // what to do with hash text
    println!("hashed text is {}",&hash__text.cyan()); // show the hashed text
    println!(
        "{} {}","your hash file contains a hashed text using:",hash_type_check(&hash__text).cyan()
    );
    }
    if select.trim() == "--hash" {
        println!("ok ... lets ask some questions and will make your hash ready :");
        println!("which hash do you want ? ");
        let mut hash_type = String::new();
        io::stdin().read_line(&mut hash_type).expect(&"error : could not read the line".red());
        println!("enter your text :");
        let mut entry = String::new();
        io::stdin().read_line(&mut entry).expect(&"error : could not read the line".red());
        println!("here is your hash : {}",hash_maker(&hash_type.trim(), &entry.trim()));
    }
    if select.trim() == "-bc" {
        bcrypt_bool = true;
    }
    if select.trim() == "-sh" {
        salty = true;
        success = false;
    }

    if select.trim() == "-st" {
        let mut custom = String::new();
    let mut file = File::open("ask.txt").expect("file does not exist");
    file.read_to_string(&mut custom).expect("file does not exist");
    print!("your ask.txt file status : ");
    if custom.is_empty() {
        println!("empty");
    } else {
        println!("exist");
    }
    }

    // hash file detection section 
    let file_path = "hash.txt";
    let _file = File::open(file_path)
        .expect("failed to open the file ");
    let hashed_text = hash__text; // rename hashed text in hash.txt

    // lunch dictionary attack
    if success == false && dictionary_attack == true && th == false {
    println!("starting dictionary attack ...");
    let wordlist_file_name = "wordlist.txt"; // name of the file 
    let file = File::open(wordlist_file_name)
        .expect("failed to open the file");
    let reader = io::BufReader::new(file);
    let mut could_crack = false;
    for (_index,line) in reader.lines().enumerate() {
        
        let lines_in_wordlist = line.expect("failed to read the line "); // to make string 
        if str::from_utf8(lines_in_wordlist.as_bytes()).is_err(){
            continue;
        }

        let result_hash_making = hash_maker(&hash_type_check(&hashed_text), &lines_in_wordlist);
        if result_hash_making.to_lowercase() == hashed_text.trim().to_lowercase() {
            println!("{} {}","Your password is".green(), lines_in_wordlist.yellow().bold());
            success = true;
            could_crack = true;

            break;
        }
    }
    if could_crack == false {
        println!("{}","dictionary attack failed".red());
    }
    }
    // lunch brute force attack
    if success == false && brute_force == true && th == false {
    println!("starting brute force ... ");
    println!("enter your cap : ( like 4 digits 6 digits ...) {}","warning : any number more than 8 digit will result in a very long operation keep this in mind".bright_red());
    let mut  cap = String::new();
    let mut number = 0;
    io::stdin().read_line(&mut cap).expect("something went wrong");
    if cap.trim().is_empty() {
        cap = "8".to_string();
    }
    let cap : u8 = cap.trim().parse().unwrap();
    let hash_type = hash_type_check(&hashed_text);
    println!("understood ... your cap is {} and brute force engaged ",cap);
    let mut could_crack = false;
    while number.to_string().len() != cap.into() {
        number += 1;
        let created_hash = hash_maker(&hash_type,&number.to_string());
        if created_hash == *hashed_text {
            println!("{} {}","your password is".green(), number.to_string().yellow().bold());
            could_crack = true;
            // success = true;
            break;
        }
    }
    if could_crack == false {
        println!("{}","brute force failed".red());
    }
}
    // bcrypt phase 
    if success == false && bcrypt_bool == true {
        println!("starting dictionary attack for bcrypt ...");
        let wordlist_file_name = "wordlist.txt"; // name of the file 
    let file = File::open(wordlist_file_name)
        .expect("failed to open the file");
    let reader = io::BufReader::new(file);
    let mut could_crack = false;
    for (_index,line) in reader.lines().enumerate() {
        let line_in_wordlist = line.expect("failed to read the line ");
        if str::from_utf8(&line_in_wordlist.as_bytes()).is_err(){
            continue;
        }
        
        let hashed = verify(&line_in_wordlist, &hashed_text).expect("failed to gt hash");
        if hashed {
            println!("your password is {}",&line_in_wordlist.yellow().bold());
            success =true;
            could_crack = true;
            break;
        }
    }
    if could_crack == false {
        println!("{}","dictionary attack failed".red());
    }
    }
    // salt cracker
    if success == false && salty == true {
        println!("enter your salt :");
        let mut salt_text = String::new();
        io::stdin().read_line(&mut salt_text);
        println!("your decrypted hash is : {}",salty_breaker(salt_text.trim().to_string()).yellow().bold());
    }
    // thread based dictionary attack
    if success == false && dictionary_attack == true && th == true {

    let mut container: Vec<String> = vec![];
    let vec_ready = false;

    println!("starting dictionary attack using threads ...");
    let wordlist_file_name = "wordlist.txt"; // name of the file 
    let file = File::open(wordlist_file_name)
        .expect("failed to open the file");
    let reader = io::BufReader::new(file);
    let mut could_crack = false;
    for (_index,line) in reader.lines().enumerate() {
        let lines_in_wordlist = line.expect("failed to read the line "); // to make string 
        if str::from_utf8(lines_in_wordlist.as_bytes()).is_err(){
            continue;
        }
        container.push(lines_in_wordlist);
        if container.len() == 8 {
            // do stuff
            container.par_iter().for_each(|word| {
                let temp_hash = hash_maker(&hash_type_check(&hashed_text), &word);
                if temp_hash == hashed_text {
                    println!("i found the pasword : {}",word.to_string().yellow().bold());

                }
            });
            // do stuff
            container.clear();
        }
    }
    if could_crack == false {
        println!("{}","dictionary attack failed".red());
    }
    }
}