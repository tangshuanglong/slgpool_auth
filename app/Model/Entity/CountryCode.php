<?php declare(strict_types=1);


namespace App\Model\Entity;

use Swoft\Db\Annotation\Mapping\Column;
use Swoft\Db\Annotation\Mapping\Entity;
use Swoft\Db\Annotation\Mapping\Id;
use Swoft\Db\Eloquent\Model;


/**
 * 
 * Class CountryCode
 *
 * @since 2.0
 *
 * @Entity(table="country_code")
 */
class CountryCode extends Model
{
    /**
     * 国家码
     *
     * @Column(name="area_code", prop="areaCode")
     *
     * @var string
     */
    private $areaCode;

    /**
     * 国家id
     *
     * @Column(name="country_id", prop="countryId")
     *
     * @var int
     */
    private $countryId;

    /**
     * 国家码信息表
     * @Id()
     * @Column()
     *
     * @var int
     */
    private $id;

    /**
     * 类型名称,英文
     *
     * @Column(name="name_cn", prop="nameCn")
     *
     * @var string
     */
    private $nameCn;

    /**
     * 类型名称,英文
     *
     * @Column(name="name_en", prop="nameEn")
     *
     * @var string
     */
    private $nameEn;


    /**
     * @param string $areaCode
     *
     * @return self
     */
    public function setAreaCode(string $areaCode): self
    {
        $this->areaCode = $areaCode;

        return $this;
    }

    /**
     * @param int $countryId
     *
     * @return self
     */
    public function setCountryId(int $countryId): self
    {
        $this->countryId = $countryId;

        return $this;
    }

    /**
     * @param int $id
     *
     * @return self
     */
    public function setId(int $id): self
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @param string $nameCn
     *
     * @return self
     */
    public function setNameCn(string $nameCn): self
    {
        $this->nameCn = $nameCn;

        return $this;
    }

    /**
     * @param string $nameEn
     *
     * @return self
     */
    public function setNameEn(string $nameEn): self
    {
        $this->nameEn = $nameEn;

        return $this;
    }

    /**
     * @return string
     */
    public function getAreaCode(): ?string
    
    {
        return $this->areaCode;
    }

    /**
     * @return int
     */
    public function getCountryId(): ?int
    
    {
        return $this->countryId;
    }

    /**
     * @return int
     */
    public function getId(): ?int
    
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getNameCn(): ?string
    
    {
        return $this->nameCn;
    }

    /**
     * @return string
     */
    public function getNameEn(): ?string
    
    {
        return $this->nameEn;
    }


}
