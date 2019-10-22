package com.easybusiness.usermanagement.services;

import java.util.List;

import org.springframework.http.ResponseEntity;

import com.easybusiness.usermanagement.DTO.LoginDTO;
import com.easybusiness.usermanagement.DTO.UserAcademicsDTO;
import com.easybusiness.usermanagement.DTO.UserDTO;
import com.easybusiness.usermanagement.DTO.UserLoginDetailsDTO;
import com.easybusiness.usermanagement.DTO.UserProfessionDTO;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserLoginDetails;

public interface UserService {

    public ResponseEntity<UserDTO> getUser(String username);

    public ResponseEntity<UserDTO> persistUser(UserDTO user);

    public List<UserDTO> populateUserList();

    public UserDTO populateOneUserDetails(Long userId);

    public void destroyUser(Long userId);

    public List<UserDTO> getFieldEq(final Class<UserDTO> type, final String propertyName, final Object value, int offset,
	    int size);

    public void persistUser(UserDTO loggedUser, boolean changePassword);

    public void activateUser(Long userId);

    public void deActivateUser(Long userId);

    public UserDTO getActiveUser(String email);
    

    ResponseEntity<UserDTO> updateUser(UserDTO userDTO);

    //List<UserProfessionDTO> getUserProfession(String userId);

    ResponseEntity<UserProfessionDTO> persistUserProfession(UserProfessionDTO userProfession);

    ResponseEntity<UserProfessionDTO> updateUserProfession(UserProfessionDTO userProfession);

    List<UserAcademicsDTO> getUserAcademics(Long userId);

    ResponseEntity<UserAcademicsDTO> persistUserAcademics(UserAcademicsDTO userAcademics);

    ResponseEntity<UserAcademicsDTO> updateUserAcademics(UserAcademicsDTO userAcademics);

	List<UserProfessionDTO> getUserProfession(Long userId);
    
    

    public UserLoginDetails LogoutUser(String loginToken) throws Exception;

	UserLoginDetails getLoginDetails(String userName, String password) throws Exception;

	
}
