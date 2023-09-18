package pseudonym.salts_repo_model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model for a repository storing encrypted salts for a collection of projects.
 */
public class SaltsRepo {
    public String storage_key_salt = null;
    public List<Project> salts = new ArrayList<Project>();
}
