package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.springframework.stereotype.Repository;

import com.easybusiness.usermanagement.entity.UserBankMap;
import com.easybusiness.usermanagement.repository.CustomRepository.UserBankMapCustomRepository;

@Transactional
@Repository
public class UserBankMapRepositoryImpl implements UserBankMapCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserBankMap getUserBankMapById(Long userBankMapId) {
	return entityManager.find(UserBankMap.class, userBankMapId);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<UserBankMap> getAllUserBankMaps() {
	String hql = "FROM UserBankMap as userBankMap ORDER BY userBankMap.id";
	return (List<UserBankMap>) entityManager.createQuery(hql).getResultList();
    }

    @Override
    public void addUserBankMap(UserBankMap userBankMap) {
	entityManager.merge(userBankMap);
    }

    @Override
    public void updateUserBankMap(UserBankMap userBankMap) {
	UserBankMap userBankMapItem = getUserBankMapById(userBankMap.getId());
	/*
	 * menu.setTitle(Menu.getTitle()); menu.setCategory(Menu.getCategory());
	 */
	entityManager.flush();
    }

    @Override
    public void deleteUserBankMap(Long userBankMapId) {
	entityManager.remove(getUserBankMapById(userBankMapId));
    }

}
