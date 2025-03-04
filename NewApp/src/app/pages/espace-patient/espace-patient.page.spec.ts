import { ComponentFixture, TestBed } from '@angular/core/testing';
import { EspacePatientPage } from './espace-patient.page';

describe('EspacePatientPage', () => {
  let component: EspacePatientPage;
  let fixture: ComponentFixture<EspacePatientPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(EspacePatientPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
