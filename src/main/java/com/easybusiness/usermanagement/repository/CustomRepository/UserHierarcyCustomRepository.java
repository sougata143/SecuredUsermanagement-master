package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.DTO.UserHierarcyDTO;
import com.easybusiness.usermanagement.entity.UserHierarchy;

public interface UserHierarcyCustomRepository {

	UserHierarchy getUserhierarcyById(long id);
	
	void deleteHierarcy(long id);
	
	void updateHierarcy(UserHierarcyDTO hierarcyDTO);
	
	void addHierarcy(UserHierarchy hierarcy);
	
	List<UserHierarchy> getAllHierarcy();
	
}
