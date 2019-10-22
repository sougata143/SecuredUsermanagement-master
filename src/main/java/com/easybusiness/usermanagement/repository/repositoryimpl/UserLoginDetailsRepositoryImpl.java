package com.easybusiness.usermanagement.repository.repositoryimpl;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.DTO.UserLoginDetailsDTO;
import com.easybusiness.usermanagement.entity.UserLoginDetails;
import com.easybusiness.usermanagement.repository.CustomRepository.UserLoginDetailsCustomRepository;


@Transactional
@Repository
public class UserLoginDetailsRepositoryImpl implements UserLoginDetailsCustomRepository {

	@PersistenceContext
    private EntityManager entityManager;

	
	@Override
	public UserLoginDetails getLoginDetailsByUserId(Long userId) {
		String hql = "FROM UserLoginDetails as login WHERE login.userId = ?";
		return (UserLoginDetails) entityManager.createQuery(hql).setParameter(1, userId).getSingleResult();
	}

	@Override
	public UserLoginDetails getLoginDetailsByLoginToken(String loginToken) {
		return entityManager.find(UserLoginDetails.class, loginToken);
	}


	@Override
	public void saveLogin(UserLoginDetails login) {
		entityManager.merge(login);
		
	}

	@Override
	public UserLoginDetails update(UserLoginDetails userLoginDetails) {
		return entityManager.merge(userLoginDetails);
	}

	@Override
	public UserLoginDetails updateCustom(String loginToken) {
		UserLoginDetails userLoginDetails = entityManager.find(UserLoginDetails.class, loginToken);
		userLoginDetails.setIsActive("N");
		return null;
	}

}
