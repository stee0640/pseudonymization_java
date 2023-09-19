package pseudonym;

import java.security.SecureRandom;
import java.util.HexFormat;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import pseudonym.encrypted_salt.EncryptedSalt;
import pseudonym.pseudonymizer.Pseudonymizer;
import pseudonym.salts_repo_model.Project;
import pseudonym.salts_repo_model.SaltsRepo;
import pseudonym.storage_password.StoragePassword;

public class Main {

    /**
     * Generates a sample collection of encrypted project salts used for pseudonymization
     * 
     * @param storage_key_salt a salt used to the storage key from a password
     * @param storage_key key for encrypting all project specific pseudonymization salts in the salts_repo
     * @return a SaltsRepo class storing a collection of encrypted project salts
     */
    private static SaltsRepo generate_sample_salts_repo(byte[] storage_key_salt, byte[] storage_key) {

        Project p1 = new Project();
        p1.encrypted_salt = new EncryptedSalt().generate(storage_key).dump();
        p1.project_id = "1";
        p1.shorthand_name = "project1";

        Project p2 = new Project();
        p2.encrypted_salt = new EncryptedSalt().generate(storage_key).dump();
        p2.project_id = "2";
        p2.shorthand_name = "project2";

        SaltsRepo salts_repo = new SaltsRepo();
        salts_repo.storage_key_salt = HexFormat.of().formatHex(storage_key_salt);
        salts_repo.salts.add(p1);
        salts_repo.salts.add(p2);
        return salts_repo;
    }

    /**
     * The main function just contains a demo program illustrating the use of pseudonymization library
     */
    public static void main(String[] args) {

        // Generate a storage key
        String storage_password = "KrypTerinG";
        byte[] storage_key_salt = new byte[16];
        new SecureRandom().nextBytes(storage_key_salt);
        byte[] storage_key = new StoragePassword(storage_key_salt).derive_key(storage_password);

        // Generate a sample collection of encrypted project salts and dump it as a storage example
        SaltsRepo salts_repo = generate_sample_salts_repo(storage_key_salt, storage_key);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(salts_repo);
        System.out.println("JSON per-project pseudonym storage:");
        System.out.println(json);

        // Generate pseudonyms for a list of CPR-numbers for the projects in the salts_repo

        String[] sample_cpr_numbers = new String[] { "0101001234", "010100-1234", "0201609996" };
        for (Project project : salts_repo.salts) {
            Pseudonymizer pseudonymizer = new Pseudonymizer(project.encrypted_salt, storage_key);

            System.out.printf("Pseudonyms for project %s (%s):\n", project.project_id, project.shorthand_name);

            for (String cpr_number : sample_cpr_numbers) {
                String pseudonymized_cpr_number = HexFormat.of().formatHex(pseudonymizer.pseudonym(cpr_number));
                System.out.println(pseudonymized_cpr_number);
            }
        }
    }
}
