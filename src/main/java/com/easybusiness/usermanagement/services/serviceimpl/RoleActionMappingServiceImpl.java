package com.easybusiness.usermanagement.services.serviceimpl;

import static com.easybusiness.usermanagement.constant.UserManagementConstant.USER_HOST_SERVER;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.easybusiness.usermanagement.DTO.RoleActionMapDTO;
import com.easybusiness.usermanagement.DTO.RoleDTO;
import com.easybusiness.usermanagement.dao.RoleActionMapDao;
import com.easybusiness.usermanagement.dao.RoleDao;
import com.easybusiness.usermanagement.entity.Role;
import com.easybusiness.usermanagement.entity.RoleActionMap;
import com.easybusiness.usermanagement.services.RoleActionMappingService;


/*
 * Service and RestController class for ROLE_ACTION_MAP_MASTER table
 */
@RestController
@RequestMapping("/easybusiness/roleaction/")
public class RoleActionMappingServiceImpl implements RoleActionMappingService {

    @Autowired
    RoleActionMapDao roleActionMapDao;

    @Autowired
    RoleDao roleDao;

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.roletoaction.RoleActionMappingService#getActionByRoleId(java.lang.Long)
     * fetching RoleActionMap by roleid
     * GET method for ROLE_ACTION_MAP_MASTER table with param roleid
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getActionByRoleId/{roleid}", method = RequestMethod.GET)
    @ResponseBody
    public List<RoleActionMapDTO> getActionByRoleId(@PathVariable("roleid") Long roleId) {

	Role role = roleDao.findRoleById(roleId).get();
	List<RoleActionMap> roleActionMapEntityList = roleActionMapDao.findByRole(role);
	List<RoleActionMapDTO> roleActionMapDTOList = new ArrayList<RoleActionMapDTO>();
	roleActionMapEntityList.forEach(roleActionMapEntity -> {
	    RoleActionMapDTO roleActionMapDTO = prepareRoleActionMapDTO(roleActionMapEntity);
	    roleActionMapDTOList.add(roleActionMapDTO);
	});
	return roleActionMapDTOList;

    }

    /*
     * preparing RoleActionMapDTO from RoleActionMap entity
     */
    private RoleActionMapDTO prepareRoleActionMapDTO(RoleActionMap roleActionMapEntity) {
	RoleActionMapDTO roleActionMapDTO = new RoleActionMapDTO();
	roleActionMapDTO.setCreateAllowed(roleActionMapEntity.getCreateAllowed());
	roleActionMapDTO.setDeleteAllowed(roleActionMapEntity.getDeleteAllowed());
	roleActionMapDTO.setDownloadAllowed(roleActionMapEntity.getDownloadAllowed());
	roleActionMapDTO.setFromDate(roleActionMapEntity.getFromDate());
	roleActionMapDTO.setId(roleActionMapEntity.getId());
	roleActionMapDTO.setIsEnable(roleActionMapEntity.getIsEnable());
	roleActionMapDTO.setModifiedBy(roleActionMapEntity.getModifiedBy());
	roleActionMapDTO.setModifiedOn(roleActionMapEntity.getModifiedOn());
	roleActionMapDTO.setPrintAllowed(roleActionMapEntity.getPrintAllowed());
	roleActionMapDTO.setRole(prepareRoleDetails(roleActionMapEntity.getRole()));
	roleActionMapDTO.setSelectAllowed(roleActionMapEntity.getSelectAllowed());
	roleActionMapDTO.setToDate(roleActionMapEntity.getToDate());
	roleActionMapDTO.setUpdateAllowed(roleActionMapEntity.getUpdateAllowed());
	roleActionMapDTO.setUploadAllowed(roleActionMapEntity.getUploadAllowed());
	roleActionMapDTO.setViewAllowed(roleActionMapEntity.getViewAllowed());
	return roleActionMapDTO;
    }

    
    /*
     * preparing RoleDTO from Role entity
     */
    private RoleDTO prepareRoleDetails(Role role) {
	RoleDTO roleDTO = new RoleDTO();
	roleDTO.setId(role.getId());
	roleDTO.setRole(role.getRole());
	roleDTO.setFromDate(role.getFromDate());
	roleDTO.setIsEnable(role.getIsEnable());
	roleDTO.setModifiedBy(role.getModifiedBy());
	roleDTO.setModifiedOn(role.getModifiedOn());
	roleDTO.setToDate(role.getToDate());
	return roleDTO;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.roletoaction.RoleActionMappingService#persistRoleActionMapping(com.easybusiness.usermanagement.DTO.RoleActionMapDTO)
     * mapping role action
     * POST method for ROLE_ACTION_MAP_MASTER table with RoleActionMapDTO request body
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "mapRoleAction", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<RoleActionMapDTO> persistRoleActionMapping(@RequestBody RoleActionMapDTO roleActionMapDTO) {

	RoleActionMap roleActionEntity = new RoleActionMap();
	roleActionEntity.setCreateAllowed(roleActionMapDTO.getCreateAllowed());
	roleActionEntity.setDeleteAllowed(roleActionMapDTO.getDeleteAllowed());
	roleActionEntity.setDownloadAllowed(roleActionMapDTO.getDownloadAllowed());
	roleActionEntity.setFromDate(roleActionMapDTO.getFromDate());
	roleActionEntity.setId(roleActionMapDTO.getId());
	roleActionEntity.setIsEnable(roleActionMapDTO.getIsEnable());
	roleActionEntity.setModifiedBy(roleActionMapDTO.getModifiedBy());
	roleActionEntity.setModifiedOn(roleActionMapDTO.getModifiedOn());
	roleActionEntity.setPrintAllowed(roleActionMapDTO.getPrintAllowed());
	
	Role role = roleDao.findRoleById(roleActionMapDTO.getRole().getId()).get();
	roleActionEntity.setRole(roleDao.findRoleById(roleActionMapDTO.getRole().getId()).get());
	
	roleActionEntity.setSelectAllowed(roleActionMapDTO.getSelectAllowed());
	roleActionEntity.setToDate(roleActionMapDTO.getToDate());
	roleActionEntity.setUpdateAllowed(roleActionMapDTO.getUpdateAllowed());
	roleActionEntity.setUploadAllowed(roleActionMapDTO.getUploadAllowed());
	roleActionEntity.setViewAllowed(roleActionMapDTO.getViewAllowed());
	roleActionMapDao.addRoleActionMap(roleActionEntity);
	return new ResponseEntity<RoleActionMapDTO>(roleActionMapDTO, HttpStatus.CREATED);

    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.roletoaction.RoleActionMappingService#destroyRoleActionMapping(java.lang.Long)
     * Destroying RoleActionMap by mappingid
     * DELETE method for ROLE_ACTION_MAP_MASTER table with mappingid param
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "destroyRoleActionMapping/{mappingid}", method = RequestMethod.DELETE)
    @ResponseBody
    public void destroyRoleActionMapping(@PathVariable("mappingid") Long mappingId) {

	roleActionMapDao.deleteRoleActionMap(mappingId);
    }

    @Override
    public List<RoleActionMapDTO> getFieldEq(Class<RoleActionMapDTO> type, String propertyName, Object value,
	    int offset, int size) {
	return null;
    }

}
