package com.easybusiness.usermanagement.repository.repositoryimpl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import com.easybusiness.usermanagement.DTO.UserHierarcyDTO;
import com.easybusiness.usermanagement.entity.UserHierarchy;
import com.easybusiness.usermanagement.repository.CustomRepository.UserHierarcyCustomRepository;

public class UserHierarcyRepositoryImpl implements UserHierarcyCustomRepository {
	
	@PersistenceContext
    private EntityManager entityManager;


	@Override
	public UserHierarchy getUserhierarcyById(long id) {
		return entityManager.find(UserHierarchy.class, id);
	}

	@Override
	public void deleteHierarcy(long id) {
		entityManager.remove(getUserhierarcyById(id));

	}

	@Override
	public void updateHierarcy(UserHierarcyDTO hierarcy) {
		
		UserHierarchy userHierarchy = entityManager.find(UserHierarchy.class, hierarcy.getHierarcyId());
		
		/*userHierarchy.setFromDate(hierarcy.getFromDate());
		userHierarchy.setHrManager(hierarcy.getHrManager());
		userHierarchy.setModBy(hierarcy.getModBy());
		userHierarchy.setModOn(hierarcy.getModOn());
		userHierarchy.setPracticeMaster(hierarcy.getPracticeMaster());
		userHierarchy.setPriSupervisor(hierarcy.getPriSupervisor());
		userHierarchy.setPrjAllocDate(hierarcy.getPrjAllocDate());
		userHierarchy.setPrjReleaseDate(hierarcy.getPrjReleaseDate());
		userHierarchy.setProjectMaster(hierarcy.getProjectMaster());
		userHierarchy.setStatus(hierarcy.getStatus());
		userHierarchy.setToDate(hierarcy.getToDate());
		userHierarchy.setUser(hierarcy.getUser());*/
		
		entityManager.merge(userHierarchy);

	}

	@Override
	public void addHierarcy(UserHierarchy hierarcy) {
		entityManager.persist(hierarcy);

	}

	@Override
	public List<UserHierarchy> getAllHierarcy() {
		String hql = "FROM UserHierarchy as hierarcy ORDER BY hierarcy.HierarcyId";
		return (List<UserHierarchy>) entityManager.createQuery(hql).getResultList();
	}

}
