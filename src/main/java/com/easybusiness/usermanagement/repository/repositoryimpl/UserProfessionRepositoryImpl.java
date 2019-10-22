package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserProfession;
import com.easybusiness.usermanagement.repository.CustomRepository.UserProfessionCustomRepository;

@Transactional
@Repository
public class UserProfessionRepositoryImpl implements UserProfessionCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void addUserProfession(UserProfession userProfession) {
	entityManager.merge(userProfession);

    }

    @Override
    public List<UserProfession> getAllUserProfessions() {
	// TODO Auto-generated method stub
	return null;
    }

    @Override
    public void updateUserProfession(UserProfession userProfession) {
	entityManager.merge(userProfession);
	
    }

}
