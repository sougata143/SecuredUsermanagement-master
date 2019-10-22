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

import com.easybusiness.usermanagement.DTO.DesignationDto;
import com.easybusiness.usermanagement.dao.DesignationDao;
import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.services.DesignationService;


/*
 * Service and RestController class for DESIGNATION
 */
@RestController
@RequestMapping("/easybusiness/designation/")
public class DesignationServiceImpl implements DesignationService {

    @Autowired
    private DesignationDao desigDao;

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.designation.DesignationService#getDesignationByName(java.lang.String)
     * fetching designation by desigName
     * GET method for DESIGNATION table with param desigName
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getDesignationByName/{desigName}", method = RequestMethod.GET)
    @ResponseBody
    public DesignationDto getDesignationByName(@PathVariable("desigName") String desigName) {

	Designation dept = desigDao.findByDesigName(desigName.toUpperCase());
	return prepareDesignationDetails(dept);
    }

    
    /*
     * preparing DesignationDTO from Designation entity
     */
    private DesignationDto prepareDesignationDetails(Designation desig) {
    	DesignationDto DesignationDTO = new DesignationDto();
	DesignationDTO.setId(desig.getId());
	DesignationDTO.setDesig(desig.getDesig());
	return DesignationDTO;
    }

    @Override
    public List<DesignationDto> getDesignationAsPerCriteria(String whereClause) {

	return null;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.designation.DesignationService#addDesignation(com.easybusiness.usermanagement.DTO.DesignationDto)
     * saving designation to database 
     * POST method for DESIGNATION table with DesignationDTO request body
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "addDesignation", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<DesignationDto> addDesignation(@RequestBody DesignationDto desigModel) {

	desigDao.addDesignation(prepareDesignationEntity(desigModel));
	return new ResponseEntity<DesignationDto>(desigModel, HttpStatus.CREATED);

    }

    /*
     * preparing DesignationEntity from DesignationDTO
     */
    private Designation prepareDesignationEntity(DesignationDto desigDTO) {
	Designation desigEntity = new Designation();
	desigEntity.setDesig(desigDTO.getDesig());
	return desigEntity;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.designation.DesignationService#getAllDesignations()
     * fetching all designatons
     * GET method for DESIGNATION table
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getAllDesignations", method = RequestMethod.GET)
    @ResponseBody
    public List<DesignationDto> getAllDesignations() throws Exception {
	List<Designation> deptList = desigDao.findAll();
	List<DesignationDto> deptModelList = new ArrayList<DesignationDto>();
	deptList.forEach(deptEntity -> {
		DesignationDto desigModel = new DesignationDto();
	    desigModel = prepareDesignationDetails(deptEntity);
	    deptModelList.add(desigModel);

	});
	return deptModelList;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.designation.DesignationService#getDesignationById(java.lang.Long)
     * fetching Designation by desigId
     * GET method for DESIGNATION table with param desigId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getDesignationById/{desigId}", method = RequestMethod.GET)
    @ResponseBody
    public DesignationDto getDesignationById(@PathVariable("desigId") Long desigId) {

	return prepareDesignationDetails(desigDao.findDesignationById(desigId).get());
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.designation.DesignationService#deleteDesignation(java.lang.Long)
     * deleting designation by desigId
     * DELETE method for DESIGNATION table with param desigId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "deleteDesignation/{desigId}", method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<DesignationDto> deleteDesignation(@PathVariable("desigId") Long desigId) {

	// deptMenuDao.deleteDesignationMenuByDesignationId(deptId);
	Designation desig = desigDao.findDesignationById(desigId).get();
	desigDao.deleteDesignation(desigId);
	return new ResponseEntity<DesignationDto>(prepareDesignationDetails(desig), HttpStatus.OK);

    }

}
