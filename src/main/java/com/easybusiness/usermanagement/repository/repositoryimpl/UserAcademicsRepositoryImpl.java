package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserAcademics;
import com.easybusiness.usermanagement.repository.CustomRepository.UserAcademicsCustomRepository;

@Transactional
@Repository
public class UserAcademicsRepositoryImpl implements UserAcademicsCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void addUserAcademics(UserAcademics userAcademics) {
	entityManager.merge(userAcademics);

    }

    @Override
    public List<UserAcademics> getAllUserAcademics() {
	return null;
    }

    @Override
    public void updateUserAcademics(UserAcademics userAcademics) {
	entityManager.merge(userAcademics);

    }

}
